# Part 4 — Design decision record

## 1. Keep encrypted payloads in SQLite

- **Problem.** Persist uploaded content and metadata without exposing plaintext in a database backup or leaving orphaned files when operations fail.
- **Alternatives.** Plaintext files with OS ACLs, encrypted files or objects linked by a database ID, and encrypted BLOBs in SQLite.
- **Decision and justification.** Store document metadata and encrypted payloads in distinct tables in one SQLite database. A single transaction can cover content, grants and audit updates. Uploads go directly from request memory into AES-GCM. The key file lives outside the database.
- **Security concepts.** Confidentiality at rest, encryption boundaries, data minimization, transactional consistency.
- **Trade-offs.** Database exports reveal filenames, sizes, ownership and sharing relationships. SQLite serializes writes, and bounded in-memory processing limits transfer size. Larger deployments may need streaming encryption and object storage. Ordinary deletion cannot erase historical backups. [SQLite transaction documentation](https://www.sqlite.org/lang_transaction.html)

## 2. Use server-side envelope encryption

- **Problem.** Protect contents and detect tampering while keeping account sharing and password recovery independent of document keys.
- **Alternatives.** One long-lived encryption key for all files, per-upload data keys wrapped by a separate key, and public-key grants with browser-side encryption. A plain hash was also considered for integrity.
- **Decision and justification.** Use a fresh AES-256-GCM data key per upload or replacement. Wrap it with a distinct server AES-256-GCM key. Supply purpose, document ID, owner and filename as associated data. Reject invalid tags before returning any file. Use independent secrets for audit signing and cookies.
- **Security concepts.** Authenticated encryption, key separation, CSPRNG nonces, context binding and fail-closed verification.
- **Trade-offs.** The server can decrypt content and the wrapping key is sensitive. Key backup, rotation, system-level access controls and wrap-nonce usage limits matter. The prototype has no automatic rotation or rollback detection for complete previous document versions. [PyCA authenticated encryption](https://cryptography.io/en/stable/hazmat/primitives/aead/) · [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)

## 3. Combine account roles with owner-managed grants

- **Problem.** Identify users, distinguish administration from document ownership, and protect each endpoint.
- **Alternatives.** Shared accounts, global RBAC, per-document ACLs, ABAC, and self-contained versus revocable sessions.
- **Decision and justification.** Provision unique accounts and verify salted scrypt hashes. Use a time-limited opaque server session identified by a signed browser cookie. A separate global admin role enables audit review. Document authorization derives from ownership or a live viewer/editor grant checked on every operation. Add CSRF validation on POST forms.
- **Security concepts.** Authentication versus authorization, least privilege, complete mediation, discretionary access control, RBAC and session revocation.
- **Trade-offs.** Password-only authentication remains vulnerable to phishing and credential theft. Operators handle provisioning and recovery, and a compromised DB writer can manipulate policy state. A shared peer address can also cause shared throttling. [Werkzeug password utilities](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security) · [Flask web security](https://flask.palletsprojects.com/en/stable/web-security/)

## 4. Share through account grants with live revocation

- **Problem.** Let named colleagues collaborate and let owners stop future access.
- **Alternatives.** Long-lived bearer links, signed expiring download links, and account grants with optional expiry.
- **Decision and justification.** Grant Viewer or Editor access only to an active account. Read the effective policy and journal the access in the operation’s transaction. Commit share updates, expiry checks and revocations through the same database boundary. A document URL still requires a valid session and authorization.
- **Security concepts.** Least privilege, capability leakage, access revocation and transaction ordering.
- **Trade-offs.** Recipients need an account. Already-authorized requests and existing copies can outlast revocation. Browser no-store headers reduce caching, while copies intentionally saved to endpoints remain outside server control.

## 5. Authenticate audit rows and a chain checkpoint

- **Problem.** Preserve evidence that can reveal misuse and detect altered or removed audit events.
- **Alternatives.** Editable database rows, unkeyed chained hashes, HMAC-chained rows, and remote immutable retention.
- **Decision and justification.** Chain records with a dedicated HMAC-SHA-256 key and keep an authenticated checkpoint for the final row. Admin review and the operator verification command check the complete ordered history. Appends check the checkpoint and authenticate the tail event before extending the chain. Business changes and the corresponding audit insert commit together.
- **Security concepts.** Accountability, message authentication, integrity and separation of duties.
- **Trade-offs.** Full verification cost grows with the chain. Edits to older rows can remain undiscovered between full verifications. A database-only writer may remove or restore the entire database, including its matching checkpoint. Remote retention and independent checkpoints would address that residual risk. The HMAC demonstrates possession of the service key. It does not establish individual non-repudiation. [Python HMAC API](https://docs.python.org/3/library/hmac.html)
