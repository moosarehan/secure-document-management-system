# Part 3 — Controlled security tests

The tests use the application’s normal routes and a fresh temporary database, fresh service keys, three synthetic accounts and fabricated document contents. Storage integrity checks use deliberately corrupted fixtures in that temporary database. No external hosts or real documents are involved.

Run `python -m unittest discover -s tests -v` with the project’s virtual environment active. The [captured test output](part3-test-output.txt) records the actual checks. The [test source](../tests/test_security.py) contains the fixture setup, routes and assertions.

## 1. Unauthorized document access

- **Threat and asset.** A signed-out visitor or a signed-in account without a grant requests confidential document bytes.
- **Steps.** Upload the fixture as its owner. Request the download signed out and then signed in as the recipient without a grant. Check the recipient’s document list and verify the denial event.
- **Expected.** The signed-out client is sent to sign-in. The recipient receives a generic unavailable response and no document bytes.
- **Actual and evidence.** The anonymous request returned HTTP 303, the unshared request returned 404, and the file was absent from the recipient’s list. The audit verifier authenticated the denied download event. See Scenario 1 in the output.
- **Limitation and mitigation.** Stolen valid credentials inherit the account’s grants. Account disablement and session invalidation limit future use. MFA would reduce reliance on passwords.

## 2. Identifier manipulation

- **Threat and asset.** A signed-in user supplies a different validly formatted identifier to obtain a document outside their permissions.
- **Steps.** As the recipient, download the recipient’s own fixture. Exercise the same route with the owner’s fixture ID and a randomly generated nonexistent ID. Compare the resulting status and body.
- **Expected.** Own content is available. Both out-of-scope identifiers yield the same generic response.
- **Actual and evidence.** The recipient’s document returned 200. The other document and unknown ID returned 404 with identical bodies. The denial event passed audit verification. See Scenario 2.
- **Limitation and mitigation.** The test compares application responses. Timing uniformity is outside its scope. Retest identifier handling whenever new document routes are added, and rate limit repeated enumeration in a wider deployment.

## 3. Storage exposure

- **Threat and asset.** A party obtains a copy of SQLite storage holding confidential documents and operational metadata.
- **Steps.** Inspect the fixture database and its payload row without loading the wrapping key. Check plaintext absence, nonce and ciphertext sizes, and the visible filename. Then request the original contents through an authorized session.
- **Expected.** The filename and content length remain observable. The database stores authenticated ciphertext and a wrapped key, while an authorized request returns the original bytes.
- **Actual and evidence.** SQLite showed the sanitized filename, a ciphertext 16 bytes longer than the source, two 12-byte nonces, and a 48-byte wrapped key. The exact plaintext was absent from the database bytes. The authorized download matched the fixture and used attachment, no-store and nosniff headers. See Scenario 3.
- **Limitation and mitigation.** The search for fixture bytes corroborates the storage behavior. The confidentiality argument comes from AES-GCM and keeping the wrapping key separate. Database backups reveal filenames, sizes, users and relationships. A separately protected key store and selective metadata encryption would reduce the exposure.

## 4. Document modification

- **Threat and asset.** Out-of-band corruption changes the integrity of a confidential document.
- **Steps.** Verify an intact fixture, then change a byte in its authentication tag in the temporary database. Repeat verification and try the normal authorized download.
- **Expected.** The intact document verifies, while the corrupted version fails both operations and releases no document bytes.
- **Actual and evidence.** Verification returned 200 before the fixture changed. Verification and download returned 409 afterward, neither response included an attachment or the original fixture, and both failures were recorded. See Scenario 4.
- **Limitation and mitigation.** Detection does not restore the data or detect replacement with a complete older valid version. Recover a known-good backup and keep an independent version checkpoint if rollback detection is required.

## 5. Privilege misuse

- **Threat and asset.** A user exceeds their assigned rights and changes content, alters sharing, deletes a document, or accesses administrative audit data.
- **Steps.** Use a Viewer grant to download and request replacement. Promote the recipient to Editor and replace the file, then request owner-only operations. Verify the audit and document access boundaries for the admin account.
- **Expected.** A Viewer can download. An Editor can replace content. Sharing, revoking and deleting require ownership. An administrator can review logs but needs an ordinary grant to download another user’s document.
- **Actual and evidence.** Viewer download returned 200 and replacement returned 403. Editor replacement returned 303 and the owner received the updated content. Editor delete, share and revoke returned 403. Admin audit review returned 200, admin download of the unshared file returned 404 and recipient audit review returned 403. The recorded denials passed audit verification. See Scenario 5.
- **Limitation and mitigation.** An Editor can intentionally replace useful content through a legitimate operation. Version history and restoration would reduce the impact.

## 6. Permission revocation

- **Threat and asset.** A former recipient continues to use a cached document URL or existing authenticated session after an owner revokes access.
- **Steps.** Grant access, download a copy as the recipient, revoke the grant as the owner, then use the same recipient session and URL to request the document again.
- **Expected.** The new download is denied and the document disappears from the recipient’s list. Bytes downloaded before revocation remain with the recipient.
- **Actual and evidence.** The same session received 200 before revocation and 404 afterward. The recipient’s list omitted the document, the earlier copy still matched the fixture, and both the revocation and subsequent denial were authenticated in the audit chain. See Scenario 6.
- **Limitation and mitigation.** A request already authorized may continue sending bytes, and saved copies cannot be recalled. Short-lived grants or a controlled viewer can limit exposure before revocation.

## 7. Audit tampering

- **Threat and asset.** A writer with direct storage access alters or removes the investigation record.
- **Steps.** Confirm an administrator can review the intact audit trail. Modify the first fixture row, then check review. Restore that fixture row, verify the clean chain again, and remove the last row while retaining the authenticated checkpoint. Check review again.
- **Expected.** The verifier rejects both the changed row and the missing tail. The audit view returns a failure instead of displaying an unverified trail.
- **Actual and evidence.** Review returned 200 before corruption and 503 for each corrupted fixture. The application log printed a diagnostic for sequence 1 and a checkpoint mismatch for the missing tail. See Scenario 7.
- **Limitation and mitigation.** Rolling back the entire database can restore a matching older chain and checkpoint. Use independently retained authenticated checkpoints or external append-only retention to detect that case.

The suite also exercises CSRF rejection, grant and session expiry, logout invalidation, confirmed deletion of document data and grants, the 5 MiB size boundary, empty uploads, sign-in throttling, and whether a failed audit append rolls back a document deletion. The append regression fixture edits the latest event without changing its stored MAC. The delete request returns 503, the document and payload remain present, and the original contents are available after restoring the audit fixture.
