# Secure Document Management System

A CS3002 prototype for uploading confidential files, sharing them with named accounts, and verifying document and audit integrity.

## Run locally on Windows

Use Python 3.11 or newer with SQLite 3.37 or newer. From the project directory, run these PowerShell commands. When prompted, choose your own passwords of at least 12 characters.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m sdms init
.\.venv\Scripts\python.exe -m sdms create-user alice
.\.venv\Scripts\python.exe -m sdms create-user bob
.\.venv\Scripts\python.exe -m sdms create-user reviewer --role admin
.\.venv\Scripts\python.exe -m sdms serve
```

Open [the local document vault](http://127.0.0.1:5000) in your browser. On Unix-like systems, use `.venv/bin/python` in place of the Windows interpreter path.

The development server binds to loopback and uses HTTP for the local demonstration. A deployment outside loopback needs a production WSGI server and HTTPS. The WSGI factory `sdms:create_app()` enables Secure cookies. Set `SDMS_TRUSTED_HOSTS` to the intended hostnames and ensure any TLS proxy is configured to convey the request scheme safely. The prototype uses the immediate peer for login throttling.

## Try the main flow

1. Sign in as Alice and upload a synthetic file up to 5 MiB. Open its details and select **Verify integrity** or **Download**.
2. Grant Bob **Viewer** or **Editor** access, optionally with a 24-hour or 7-day expiry. Sign in as Bob in a separate browser profile. Viewers can download and verify. Editors can also replace the file.
3. Revoke Bob’s grant from Alice’s session. The file disappears from Bob’s list, and his existing document URL stops authorizing new requests.
4. Sign in as Reviewer and open **Audit trail**. The entire chain is verified before the latest 100 events are shown. Reviewing the audit trail grants no document access.

Operators can also run `python -m sdms verify-audit`, `python -m sdms reset-password USERNAME`, `python -m sdms disable-user USERNAME`, and `python -m sdms enable-user USERNAME` using the virtual environment’s interpreter. Password resets and disabling accounts invalidate their existing sessions.

## Data and keys

The default database is `instance/vault.sqlite3`. Its separate key file defaults to `.sdms-keys.json`. Override their paths with `SDMS_DATABASE` and `SDMS_KEY_FILE`. For sensitive data, put the key file in a separately protected directory, restrict filesystem access to the service account, and back it up separately. On Windows those access controls are NTFS permissions. The default database, key file and virtual environment are ignored by Git. Keep backups and generated secrets out of any source archive.

## Verify and review

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

- [Part 1 — Security research and design](docs/part1-research.md)
- Part 2 — Application in [sdms](sdms) and the setup above
- [Part 3 — Controlled security checks](docs/part3-security-tests.md)
- [Part 4 — Design decision record](docs/part4-design-decisions.md)

## Technical documentation and demonstration

- [Part 5 technical design](docs/part5-technical-design.md) covers the architecture, threat model, storage, cryptography, and access control.
- [Architecture diagram](docs/architecture.svg) shows the browser, application, SQLite, operator, and separate key file.
- [Demonstration guide](docs/demo.md) walks through sharing, revocation, audit review, and selected security tests.
- [Synthetic demo memo](docs/demo-data/project-memo.txt) is ready to upload.

| Demo screen | What it shows |
|---|---|
| [Owner document](docs/screenshots/01-owner-document.png) | Alice’s document and Bob’s Viewer grant |
| [Viewer access](docs/screenshots/02-viewer-access.png) | Bob can download and verify the shared document |
| [Revoked access](docs/screenshots/03-access-revoked.png) | Bob’s existing session receives an unavailable response after revocation |
| [Verified audit trail](docs/screenshots/04-audit-trail.png) | The administrator can correlate the grant, download, revocation, and denial |

## References and dependencies

- Flask handles routing, signed cookies and Jinja-based templates. Werkzeug handles filename normalization and salted scrypt password hashing. [Flask security documentation](https://flask.palletsprojects.com/en/stable/web-security/) · [Werkzeug utilities](https://werkzeug.palletsprojects.com/en/stable/utils/)
- PyCA cryptography provides AES-GCM. Python’s standard library provides randomness, HMAC, session-token hashing and the SQLite interface. [PyCA authenticated encryption](https://cryptography.io/en/stable/hazmat/primitives/aead/) · [Python HMAC](https://docs.python.org/3/library/hmac.html) · [Python sqlite3](https://docs.python.org/3/library/sqlite3.html)
- SQLite provides transactional persistence. [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
