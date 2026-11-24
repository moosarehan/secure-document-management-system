import os
import secrets
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from werkzeug.security import generate_password_hash

from sdms import LOGIN_FAILURE_LIMIT, MAX_FILE, PASSWORD_METHOD, SESSION_SECONDS, create_app
from sdms.storage import create_keys, initialize, load_keys, now, record, transaction, verify_audit


HTTPS = "https://localhost"
PAYLOAD = b"SDMS synthetic financial memo fixture 3921\n"


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = secrets.token_urlsafe(24)
        cls.accounts = {}
        for name in ("owner", "recipient", "auditor"):
            cls.accounts[name] = generate_password_hash(cls.password, method=PASSWORD_METHOD)

    def setUp(self):
        folder = self.enterContext(tempfile.TemporaryDirectory())
        self.db_path = Path(folder) / "vault.sqlite3"
        key_file = Path(folder) / "secure" / "keys.json"
        create_keys(key_file)
        self.audit_key = load_keys(key_file)["audit"]
        initialize(self.db_path, self.audit_key)
        self.account_ids = {}
        with transaction(self.db_path) as db:
            for username, password_hash in self.accounts.items():
                role = "admin" if username == "auditor" else "member"
                user_id = db.execute(
                    "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                    (username, password_hash, role),
                ).lastrowid
                self.account_ids[username] = user_id
                record(db, self.audit_key, None, "create_user", detail=f"user={user_id} role={role}")
        self.app = create_app({"TESTING": True, "DATABASE": self.db_path, "KEY_FILE": key_file})
        self.owner = self.sign_in("owner")
        self.doc = self.upload(self.owner)

    def get(self, client, path):
        return client.get(path, base_url=HTTPS)

    def post(self, client, path, data=None):
        with client.session_transaction(base_url=HTTPS) as browser_session:
            csrf = browser_session["csrf"]
        return client.post(path, base_url=HTTPS, data={**(data or {}), "csrf": csrf})

    def sign_in(self, username):
        client = self.app.test_client()
        self.get(client, "/login")
        response = self.post(client, "/login", {"username": username, "password": self.password})
        self.assertEqual(response.status_code, 303)
        for attribute in ("HttpOnly", "Secure", "SameSite=Lax"):
            self.assertIn(attribute, response.headers["Set-Cookie"])
        self.assertEqual(self.get(client, "/").status_code, 200)
        return client

    def upload(self, client, name="synthetic-memo.txt", contents=PAYLOAD):
        response = self.post(client, "/documents", {"file": (BytesIO(contents), name)})
        self.assertEqual(response.status_code, 303)
        return response.location

    def grant(self, role="viewer", expiry=""):
        response = self.post(self.owner, self.doc + "/share",
                             {"username": "recipient", "role": role, "duration": expiry})
        self.assertEqual(response.status_code, 303)

    def audit_outcome(self, actor, action, outcome):
        with transaction(self.db_path) as db:
            self.assertGreater(verify_audit(db, self.audit_key), 0)
            event = db.execute(
                """SELECT 1 FROM audit WHERE actor_id = ? AND action = ? AND outcome = ?
                   AND document_id = ?""",
                (self.account_ids[actor], action, outcome, self.doc.rsplit("/", 1)[1]),
            ).fetchone()
        self.assertIsNotNone(event)

    def test_01_unauthorized_document_access(self):
        recipient = self.sign_in("recipient")
        self.assertNotIn(b"synthetic-memo.txt", self.get(recipient, "/").data)
        self.assertEqual(self.get(self.app.test_client(), self.doc + "/download").status_code, 303)
        response = self.get(recipient, self.doc + "/download")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(PAYLOAD, response.data)
        self.audit_outcome("recipient", "download", "denied")
        print("Scenario 1 | anonymous redirect 303, unshared download 404, denial authenticated", flush=True)

    def test_02_route_parameter_keeps_document_scope(self):
        recipient = self.sign_in("recipient")
        permitted = self.upload(recipient, "recipient.txt", b"Recipient's own fixture")
        self.assertEqual(self.get(recipient, permitted + "/download").status_code, 200)
        existing = self.get(recipient, self.doc + "/download")
        unknown = self.get(recipient, f"/documents/{uuid4()}/download")
        self.assertEqual((existing.status_code, unknown.status_code), (404, 404))
        self.assertEqual(existing.data, unknown.data)
        self.audit_outcome("recipient", "download", "denied")
        print("Scenario 2 | own document 200, other and unknown IDs 404 with identical bodies", flush=True)

    def test_03_database_at_rest_contains_ciphertext(self):
        document_id = self.doc.rsplit("/", 1)[1]
        with transaction(self.db_path) as db:
            payload = db.execute("SELECT * FROM payloads WHERE document_id = ?", (document_id,)).fetchone()
            filename = db.execute("SELECT filename FROM documents WHERE id = ?", (document_id,)).fetchone()[0]
        self.assertEqual(filename, "synthetic-memo.txt")
        self.assertNotIn(PAYLOAD, self.db_path.read_bytes())
        self.assertEqual(len(payload["ciphertext"]), len(PAYLOAD) + 16)
        self.assertEqual(len(payload["wrapped_key"]), 48)
        self.assertEqual((len(payload["data_nonce"]), len(payload["wrap_nonce"])), (12, 12))
        download = self.get(self.owner, self.doc + "/download")
        self.assertEqual(download.data, PAYLOAD)
        self.assertEqual(download.headers["Cache-Control"], "no-store")
        self.assertTrue(download.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(download.headers["X-Content-Type-Options"], "nosniff")
        print("Scenario 3 | filename visible, fixture absent from database bytes, authorized round trip matches", flush=True)

    def test_04_corrupt_storage_blocks_plaintext(self):
        document_id = self.doc.rsplit("/", 1)[1]
        response = self.post(self.owner, self.doc + "/verify")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Integrity verified", response.data)
        with transaction(self.db_path) as db:
            ciphertext = db.execute("SELECT ciphertext FROM payloads WHERE document_id = ?",
                                    (document_id,)).fetchone()[0]
            altered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
            db.execute("UPDATE payloads SET ciphertext = ? WHERE document_id = ?", (altered, document_id))
        for method, action in ((self.post, "verify"), (self.get, "download")):
            with self.subTest(action=action):
                response = method(self.owner, self.doc + "/" + action)
                self.assertEqual(response.status_code, 409)
                self.assertNotIn("Content-Disposition", response.headers)
                self.assertNotIn(PAYLOAD, response.data)
                self.audit_outcome("owner", action, "integrity_failed")
        print("Scenario 4 | intact verification 200, corrupted verification and download 409", flush=True)

    def test_05_permissions_apply_to_each_operation(self):
        recipient = self.sign_in("recipient")
        auditor = self.sign_in("auditor")
        self.grant("viewer")
        self.assertEqual(self.get(recipient, self.doc + "/download").status_code, 200)
        self.assertEqual(self.post(recipient, self.doc + "/verify").status_code, 200)
        self.assertEqual(self.post(recipient, self.doc + "/replace").status_code, 403)
        self.audit_outcome("recipient", "replace", "denied")
        self.grant("editor")
        response = self.post(recipient, self.doc + "/replace",
                             {"file": (BytesIO(b"Revised fixture"), "revised.txt")})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.get(self.owner, self.doc + "/download").data, b"Revised fixture")
        for action in ("delete", "share", "revoke"):
            self.assertEqual(self.post(recipient, self.doc + "/" + action).status_code, 403)
            self.audit_outcome("recipient", action, "denied")
        self.assertEqual(self.get(auditor, self.doc + "/download").status_code, 404)
        self.assertEqual(self.get(auditor, "/audit").status_code, 200)
        self.assertEqual(self.get(recipient, "/audit").status_code, 403)
        print("Scenario 5 | viewer replacement 403, editor replacement 303, owner-only operations 403, admin download 404", flush=True)

    def test_06_revocation_applies_to_active_sessions(self):
        recipient = self.sign_in("recipient")
        self.grant()
        saved_copy = self.get(recipient, self.doc + "/download")
        self.assertEqual(saved_copy.status_code, 200)
        self.assertEqual(saved_copy.data, PAYLOAD)
        response = self.post(self.owner, self.doc + "/revoke", {"recipient": self.account_ids["recipient"]})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.get(recipient, self.doc + "/download").status_code, 404)
        self.assertNotIn(b"synthetic-memo.txt", self.get(recipient, "/").data)
        self.assertEqual(saved_copy.data, PAYLOAD)
        self.audit_outcome("owner", "revoke", "ok")
        self.audit_outcome("recipient", "download", "denied")
        print("Scenario 6 | same session 200 before and 404 after revoke, saved copy remains", flush=True)

    def test_07_audit_integrity_detects_edit_and_tail_removal(self):
        auditor = self.sign_in("auditor")
        self.assertEqual(self.get(auditor, "/audit").status_code, 200)
        with transaction(self.db_path) as db:
            db.execute("UPDATE audit SET outcome = 'altered fixture' WHERE seq = 1")
        with self.assertLogs(self.app.logger, "ERROR") as logged:
            self.assertEqual(self.get(auditor, "/audit").status_code, 503)
        self.assertIn("sequence 1", logged.output[0])
        with transaction(self.db_path) as db:
            db.execute("UPDATE audit SET outcome = 'ok' WHERE seq = 1")
            self.assertGreater(verify_audit(db, self.audit_key), 0)
            db.execute("DELETE FROM audit WHERE seq = (SELECT max(seq) FROM audit)")
        with self.assertLogs(self.app.logger, "ERROR") as logged:
            self.assertEqual(self.get(auditor, "/audit").status_code, 503)
        self.assertIn("does not match the checkpoint", logged.output[0])
        print("Scenario 7 | clean history 200, edited row and deleted tail 503 with diagnostic", flush=True)

    def test_edited_tail_blocks_document_mutation(self):
        with transaction(self.db_path) as db:
            db.execute("UPDATE audit SET outcome = 'damaged fixture' WHERE seq = (SELECT max(seq) FROM audit)")
        with self.assertLogs(self.app.logger, "ERROR") as logged:
            response = self.post(self.owner, self.doc + "/delete", {"confirm": "yes"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("Audit verification failed at sequence", logged.output[0])
        with transaction(self.db_path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM documents").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM payloads").fetchone()[0], 1)
            db.execute("UPDATE audit SET outcome = 'ok' WHERE seq = (SELECT max(seq) FROM audit)")
            self.assertGreater(verify_audit(db, self.audit_key), 0)
        self.assertEqual(self.get(self.owner, self.doc + "/download").data, PAYLOAD)
        print("Audit append | edited tail returned 503 and document deletion rolled back", flush=True)

    def test_csrf_expiry_logout_and_owner_deletion(self):
        recipient = self.sign_in("recipient")
        self.grant(expiry="24")
        self.assertEqual(self.get(recipient, self.doc + "/download").status_code, 200)
        with patch("sdms.now", return_value=now() + SESSION_SECONDS + 1):
            self.assertEqual(self.get(recipient, self.doc + "/download").status_code, 303)
        recipient = self.sign_in("recipient")
        with transaction(self.db_path) as db:
            db.execute("UPDATE grants SET expires_at = ?", (now() - 1,))
        self.assertEqual(self.get(recipient, self.doc + "/download").status_code, 404)
        self.assertEqual(self.owner.post(self.doc + "/delete", base_url=HTTPS).status_code, 400)
        self.assertEqual(self.post(self.owner, self.doc + "/delete").status_code, 400)
        self.assertEqual(self.post(self.owner, self.doc + "/delete", {"confirm": "yes"}).status_code, 303)
        with transaction(self.db_path) as db:
            for table in ("documents", "payloads", "grants"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
        cookie = self.owner.get_cookie("sdms_session")
        self.assertEqual(self.post(self.owner, "/logout").status_code, 303)
        self.owner.set_cookie(cookie.key, cookie.value)
        self.assertEqual(self.get(self.owner, "/").status_code, 303)

    def test_upload_limit_and_empty_payload(self):
        empty = self.upload(self.owner, "empty.txt", b"")
        self.assertEqual(self.get(self.owner, empty + "/download").data, b"")
        large = os.urandom(MAX_FILE)
        maximum = self.upload(self.owner, "limit.bin", large)
        self.assertEqual(self.get(self.owner, maximum + "/download").data, large)
        response = self.post(self.owner, "/documents", {"file": (BytesIO(large + b"!"), "too-large.bin")})
        self.assertEqual(response.status_code, 413)

    def test_rate_limit_counts_failed_logins(self):
        client = self.app.test_client()
        self.get(client, "/login")
        for _ in range(LOGIN_FAILURE_LIMIT):
            failure = self.post(client, "/login", {"username": "owner", "password": "invalid test password"})
            self.assertEqual(failure.status_code, 401)
        blocked = self.post(client, "/login", {"username": "owner", "password": self.password})
        self.assertEqual(blocked.status_code, 429)


if __name__ == "__main__":
    unittest.main()
