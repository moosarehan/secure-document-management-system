import hashlib
import hmac
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_NAMES = ("wrapping", "audit", "cookie")
GENESIS = bytes(32)


class AuditIntegrityError(Exception):
    pass


def now():
    return int(time.time())


def create_keys(path):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    keys = {name: os.urandom(32).hex() for name in KEY_NAMES}
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(keys, stream)
        stream.flush()
        os.fsync(stream.fileno())


def load_keys(path):
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        keys = {name: bytes.fromhex(raw[name]) for name in KEY_NAMES}
        if any(len(key) != 32 for key in keys.values()) or len(set(keys.values())) != 3:
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ValueError("Cannot load the three distinct 256-bit application keys.") from error
    return keys


def connect(path, *, create=False):
    mode = "rwc" if create else "rw"
    db = sqlite3.connect(f"{path.resolve().as_uri()}?mode={mode}", uri=True, isolation_level=None, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA secure_delete = ON")
    return db


@contextmanager
def transaction(path):
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    finally:
        db.close()


def initialize(path, audit_key):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    db = connect(path, create=True)
    try:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        db.executescript("BEGIN IMMEDIATE;\n" + schema)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            db.execute("INSERT INTO audit_head VALUES (1, 0, ?, ?)",
                       (GENESIS, mac(audit_key, "head", 0, GENESIS.hex())))
            db.execute("PRAGMA user_version = 1")
        elif version != 1:
            raise ValueError(f"Unsupported database schema version {version}.")
        verify_audit(db, audit_key)
        db.commit()
    finally:
        db.close()


def encoded(*fields):
    return json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def protect(wrapping_key, document, plaintext):
    data_key = AESGCM.generate_key(bit_length=256)
    data_nonce, wrap_nonce = os.urandom(12), os.urandom(12)
    binding = (document["id"], document["owner_id"], document["filename"])
    ciphertext = AESGCM(data_key).encrypt(data_nonce, plaintext, encoded("content-v1", *binding))
    wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, data_key, encoded("key-v1", *binding))
    return data_nonce, wrap_nonce, wrapped, ciphertext


def reveal(wrapping_key, document, payload):
    if (payload is None or len(payload["wrap_nonce"]) != 12 or len(payload["data_nonce"]) != 12
            or len(payload["wrapped_key"]) != 48 or len(payload["ciphertext"]) < 16):
        raise InvalidTag
    binding = (document["id"], document["owner_id"], document["filename"])
    key = AESGCM(wrapping_key).decrypt(
        payload["wrap_nonce"], payload["wrapped_key"], encoded("key-v1", *binding)
    )
    return AESGCM(key).decrypt(
        payload["data_nonce"], payload["ciphertext"], encoded("content-v1", *binding)
    )


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).digest()


def mac(key, *fields):
    return hmac.digest(key, encoded(*fields), "sha256")


def audit_head(db, key):
    row = db.execute("SELECT seq, last_mac, signature FROM audit_head").fetchone()
    if row is None or row["seq"] < 0 or not hmac.compare_digest(
        row["signature"], mac(key, "head", row["seq"], row["last_mac"].hex())
    ):
        raise AuditIntegrityError("The audit checkpoint could not be authenticated.")
    return row["seq"], row["last_mac"]


def check_event(key, row, seq, previous):
    *event, signature = tuple(row)
    if event[0] != seq or not hmac.compare_digest(
        signature, mac(key, "event", previous.hex(), *event)
    ):
        raise AuditIntegrityError(f"Audit verification failed at sequence {seq}.")
    return signature


def record(db, key, actor, action, outcome="ok", document_id=None, detail=None):
    seq, previous = audit_head(db, key)
    trailing_rows = db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 2").fetchall()
    actual = (trailing_rows[0]["seq"], trailing_rows[0]["mac"]) if trailing_rows else (0, GENESIS)
    if actual != (seq, previous):
        raise AuditIntegrityError("The audit tail does not match the checkpoint.")
    if trailing_rows:
        predecessor_mac = GENESIS
        if seq > 1:
            if len(trailing_rows) != 2 or trailing_rows[1]["seq"] != seq - 1:
                raise AuditIntegrityError("The audit tail is missing its predecessor.")
            predecessor_mac = trailing_rows[1]["mac"]
        check_event(key, trailing_rows[0], seq, predecessor_mac)
    event = (seq + 1, now(), actor, action, document_id, outcome, detail)
    signature = mac(key, "event", previous.hex(), *event)
    db.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (*event, signature))
    db.execute("UPDATE audit_head SET seq = ?, last_mac = ?, signature = ? WHERE singleton = 1",
               (seq + 1, signature, mac(key, "head", seq + 1, signature.hex())))


def verify_audit(db, key):
    expected_seq, expected_mac = audit_head(db, key)
    seq, previous = 0, GENESIS
    for row in db.execute("SELECT * FROM audit ORDER BY seq"):
        seq += 1
        previous = check_event(key, row, seq, previous)
    if seq != expected_seq or not hmac.compare_digest(previous, expected_mac):
        raise AuditIntegrityError("The audit history does not match the checkpoint.")
    return seq
