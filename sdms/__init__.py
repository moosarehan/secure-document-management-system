import hmac
import os
import re
import secrets
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from flask import (
    Flask, Request, abort, g, redirect, render_template, request, send_file, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .storage import (
    AuditIntegrityError, load_keys, now, protect, record, reveal, token_hash, transaction, verify_audit,
)


MAX_FILE = 5 * 1024 * 1024
SESSION_SECONDS = 8 * 60 * 60
LOGIN_WINDOW = 5 * 60
LOGIN_FAILURE_LIMIT = 10
USERNAME = re.compile(r"[a-z0-9_.-]{3,40}", re.ASCII)
PASSWORD_METHOD = "scrypt:65536:8:1"
ROOT = Path(__file__).resolve().parent.parent
PERMISSIONS = {"viewer": 1, "editor": 2, "owner": 3}


class MemoryUploadRequest(Request):
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return BytesIO()


def paths():
    return (
        Path(os.environ.get("SDMS_DATABASE", ROOT / "instance" / "vault.sqlite3")).resolve(),
        Path(os.environ.get("SDMS_KEY_FILE", ROOT / ".sdms-keys.json")).resolve(),
    )


def create_app(config=None):
    app = Flask(__name__, static_folder=None)
    app.request_class = MemoryUploadRequest
    db_path, key_path = paths()
    app.config.from_mapping(
        DATABASE=db_path,
        KEY_FILE=key_path,
        MAX_CONTENT_LENGTH=MAX_FILE + 64 * 1024,
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=8,
        PERMANENT_SESSION_LIFETIME=SESSION_SECONDS,
        SESSION_COOKIE_NAME="sdms_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_REFRESH_EACH_REQUEST=False,
        TRUSTED_HOSTS=os.environ.get("SDMS_TRUSTED_HOSTS", "localhost,127.0.0.1").split(","),
    )
    if config:
        app.config.update(config)
    app.config["DATABASE"] = Path(app.config["DATABASE"])
    if not app.config["DATABASE"].is_file():
        raise ValueError("Database is missing. Run python -m sdms init.")
    keys = load_keys(Path(app.config["KEY_FILE"]))
    app.secret_key = keys["cookie"]
    dummy_hash = generate_password_hash(secrets.token_hex(32), method=PASSWORD_METHOD)

    def log(db, action, outcome="ok", document_id=None, detail=None):
        actor = g.user["id"] if g.user is not None else None
        record(db, keys["audit"], actor, action, outcome, document_id, detail)

    @app.before_request
    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            submitted = request.form.get("csrf", "")
            if not submitted.isascii() or not hmac.compare_digest(session["csrf"], submitted):
                abort(400, "The form expired or could not be verified. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.template_filter("utc")
    def utc(value):
        if value is None:
            return "No expiry"
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    @app.errorhandler(AuditIntegrityError)
    def audit_failure(error):
        app.logger.error("Audit integrity failure: %s", error)
        return render_template("error.html", code=503,
                               message="Audit integrity verification failed. Contact the operator."), 503

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def request_error(error):
        return render_template("error.html", code=error.code, message=error.description), error.code

    def failure(code, message):
        return render_template("error.html", code=code, message=message), code

    def authenticated(view):
        @wraps(view)
        def wrapper(**kwargs):
            with transaction(app.config["DATABASE"]) as db:
                g.user = None
                token = session.get("token")
                if token:
                    g.user = db.execute(
                        """SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON s.user_id = u.id
                           WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1""",
                        (token_hash(token), now()),
                    ).fetchone()
                if g.user is None:
                    if token:
                        session.clear()
                    return redirect(url_for("login"), code=303)
                return view(db, **kwargs)
        return wrapper

    def document_route(required, action):
        def decorate(view):
            @wraps(view)
            @authenticated
            def wrapper(db, document_id, **kwargs):
                doc_id = str(document_id)
                doc = db.execute(
                    """SELECT d.*, CASE WHEN d.owner_id = ? THEN 'owner' ELSE g.role END AS access
                       FROM documents d LEFT JOIN grants g
                           ON g.document_id = d.id AND g.user_id = ?
                           AND (g.expires_at IS NULL OR g.expires_at > ?)
                       WHERE d.id = ?""",
                    (g.user["id"], g.user["id"], now(), doc_id),
                ).fetchone()
                if doc is None or doc["access"] is None:
                    log(db, action, "denied", doc_id, "not_visible")
                    return failure(404, "Document unavailable.")
                if PERMISSIONS[doc["access"]] < PERMISSIONS[required]:
                    log(db, action, "denied", doc_id, "insufficient_role")
                    return failure(403, "Your document role does not allow this action.")
                return view(db, doc, **kwargs)
            return wrapper
        return decorate

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        peer = request.remote_addr or "unknown"
        with transaction(app.config["DATABASE"]) as db:
            failures = db.execute(
                """SELECT count(*) FROM audit WHERE action = 'login' AND outcome = 'failed'
                   AND detail = ? AND recorded_at > ?""",
                (peer, now() - LOGIN_WINDOW),
            ).fetchone()[0]
            if failures >= LOGIN_FAILURE_LIMIT:
                return render_template("login.html", error="Too many failed sign-ins. Try again in five minutes."), 429
            user = None
            if USERNAME.fullmatch(username):
                user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            password_hash = user["password_hash"] if user else dummy_hash
            valid = len(password) <= 256 and check_password_hash(password_hash, password)
            if not valid or not user or not user["active"]:
                record(db, keys["audit"], user["id"] if user else None, "login", "failed", detail=peer)
                return render_template("login.html", error="Invalid username or password."), 401
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now(),))
            if session.get("token"):
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(session["token"]),))
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                       (token_hash(token), user["id"], now() + SESSION_SECONDS))
            record(db, keys["audit"], user["id"], "login", detail=peer)
        session.clear()
        session.permanent = True
        session["token"] = token
        return redirect(url_for("index"), code=303)

    @app.post("/logout")
    @authenticated
    def logout(db):
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(session["token"]),))
        log(db, "logout")
        session.clear()
        return redirect(url_for("login"), code=303)

    @app.get("/")
    @authenticated
    def index(db):
        documents = db.execute(
            """SELECT d.*, CASE WHEN d.owner_id = ? THEN 'owner' ELSE g.role END AS access
               FROM documents d LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = ?
                   AND (g.expires_at IS NULL OR g.expires_at > ?)
               WHERE d.owner_id = ? OR g.role IS NOT NULL ORDER BY d.updated_at DESC, d.id""",
            (g.user["id"], g.user["id"], now(), g.user["id"]),
        ).fetchall()
        log(db, "list_documents")
        return render_template("index.html", documents=documents)

    def uploaded_file():
        upload = request.files.get("file")
        filename = secure_filename(upload.filename or "") if upload else ""
        if not filename or len(filename) > 150:
            abort(400, "Choose a file with a filename of at most 150 safe characters.")
        contents = upload.read(MAX_FILE + 1)
        if len(contents) > MAX_FILE:
            abort(413)
        return filename, contents

    def save_payload(db, doc, contents):
        protected = protect(keys["wrapping"], doc, contents)
        db.execute(
            """INSERT INTO payloads VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(document_id) DO UPDATE SET data_nonce = excluded.data_nonce,
                   wrap_nonce = excluded.wrap_nonce, wrapped_key = excluded.wrapped_key,
                   ciphertext = excluded.ciphertext""",
            (doc["id"], *protected),
        )

    @app.post("/documents")
    @authenticated
    def upload(db):
        filename, contents = uploaded_file()
        doc_id = str(uuid4())
        doc = {"id": doc_id, "owner_id": g.user["id"], "filename": filename}
        db.execute("INSERT INTO documents VALUES (?, ?, ?, ?)",
                   (doc_id, doc["owner_id"], filename, now()))
        save_payload(db, doc, contents)
        log(db, "upload", document_id=doc_id)
        return redirect(url_for("detail", document_id=doc_id), code=303)

    @app.get("/documents/<uuid:document_id>")
    @document_route("viewer", "inspect")
    def detail(db, doc):
        grants = []
        if doc["access"] == "owner":
            grants = db.execute(
                """SELECT u.id, u.username, u.active, g.role, g.expires_at FROM grants g
                   JOIN users u ON g.user_id = u.id WHERE g.document_id = ? ORDER BY u.username""",
                (doc["id"],),
            ).fetchall()
        log(db, "inspect", document_id=doc["id"])
        return render_template("document.html", doc=doc, grants=grants, timestamp=now())

    def read_document(db, doc, action):
        payload = db.execute("SELECT * FROM payloads WHERE document_id = ?", (doc["id"],)).fetchone()
        try:
            contents = reveal(keys["wrapping"], doc, payload)
        except InvalidTag:
            log(db, action, "integrity_failed", doc["id"])
            return None
        log(db, action, document_id=doc["id"])
        return contents

    @app.get("/documents/<uuid:document_id>/download")
    @document_route("viewer", "download")
    def download(db, doc):
        contents = read_document(db, doc, "download")
        if contents is None:
            return failure(409, "Document integrity verification failed.")
        return send_file(BytesIO(contents), as_attachment=True, download_name=doc["filename"],
                         mimetype="application/octet-stream", conditional=False, etag=False)

    @app.post("/documents/<uuid:document_id>/verify")
    @document_route("viewer", "verify")
    def verify(db, doc):
        contents = read_document(db, doc, "verify")
        if contents is None:
            return failure(409, "Document integrity verification failed.")
        return render_template("verified.html", doc=doc)

    @app.post("/documents/<uuid:document_id>/replace")
    @document_route("editor", "replace")
    def replace(db, doc):
        filename, contents = uploaded_file()
        updated = dict(doc, filename=filename)
        save_payload(db, updated, contents)
        db.execute("UPDATE documents SET filename = ?, updated_at = ? WHERE id = ?",
                   (filename, now(), doc["id"]))
        log(db, "replace", document_id=doc["id"])
        return redirect(url_for("detail", document_id=doc["id"]), code=303)

    @app.post("/documents/<uuid:document_id>/delete")
    @document_route("owner", "delete")
    def delete(db, doc):
        if request.form.get("confirm") != "yes":
            abort(400, "Confirm the deletion first.")
        db.execute("DELETE FROM documents WHERE id = ?", (doc["id"],))
        log(db, "delete", document_id=doc["id"])
        return redirect(url_for("index"), code=303)

    @app.post("/documents/<uuid:document_id>/share")
    @document_route("owner", "share")
    def share(db, doc):
        username = request.form.get("username", "").strip().lower()
        role = request.form.get("role")
        duration = request.form.get("duration", "")
        if role not in ("viewer", "editor") or duration not in ("", "24", "168"):
            abort(400, "Select a supported role and expiry.")
        recipient = db.execute("SELECT id FROM users WHERE username = ? AND active = 1 AND id != ?",
                               (username, g.user["id"])).fetchone()
        if recipient is None:
            abort(400, "Choose a different active account.")
        expiry = now() + 3600 * int(duration) if duration else None
        db.execute(
            """INSERT INTO grants VALUES (?, ?, ?, ?) ON CONFLICT(document_id, user_id)
               DO UPDATE SET role = excluded.role, expires_at = excluded.expires_at""",
            (doc["id"], recipient["id"], role, expiry),
        )
        log(db, "share", document_id=doc["id"], detail=f'user={recipient["id"]} role={role} expires={expiry}')
        return redirect(url_for("detail", document_id=doc["id"]), code=303)

    @app.post("/documents/<uuid:document_id>/revoke")
    @document_route("owner", "revoke")
    def revoke(db, doc):
        recipient = request.form.get("recipient", "")
        if not re.fullmatch(r"[0-9]{1,18}", recipient):
            abort(400, "Choose an existing share.")
        removed = db.execute("DELETE FROM grants WHERE document_id = ? AND user_id = ?",
                             (doc["id"], int(recipient)))
        log(db, "revoke", "ok" if removed.rowcount else "no_change", doc["id"], f"user={int(recipient)}")
        return redirect(url_for("detail", document_id=doc["id"]), code=303)

    @app.get("/audit")
    @authenticated
    def audit(db):
        if g.user["role"] != "admin":
            log(db, "audit_review", "denied")
            return failure(403, "Audit review requires an administrator account.")
        verify_audit(db, keys["audit"])
        log(db, "audit_review")
        events = db.execute(
            """SELECT a.*, u.username FROM audit a LEFT JOIN users u ON a.actor_id = u.id
               ORDER BY a.seq DESC LIMIT 100"""
        ).fetchall()
        return render_template("audit.html", events=events)

    @app.get("/style.css")
    def stylesheet():
        return send_file(Path(__file__).with_name("style.css"), mimetype="text/css")

    return app
