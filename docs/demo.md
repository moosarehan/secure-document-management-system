# Demonstration guide

Allow about five minutes. Use three separate browser profiles for `alice`, `bob`, and `reviewer`. Provision them with the [setup instructions](../README.md) and use the [synthetic project memo](demo-data/project-memo.txt). Choose local passwords at setup.

| Time | Live walkthrough | Evidence |
|---|---|---|
| 0:00 | Sign in as Alice, upload the memo, open it, and verify integrity. | [Document detail](screenshots/01-owner-document.png) |
| 0:45 | Grant Bob Viewer access. Open Bob’s profile and download the file. | [Viewer access](screenshots/02-viewer-access.png) |
| 1:30 | Keep Bob’s document tab open. Revoke the grant as Alice, then reload Bob’s tab. | [Access denied after revocation](screenshots/03-access-revoked.png) |
| 2:15 | Sign in as Reviewer and open Audit trail. Find the successful download and the denial after revocation. | [Verified audit trail](screenshots/04-audit-trail.png) |
| 3:00 | Run the isolated test suite. Show Scenario 3 for storage confidentiality, Scenario 4 for document integrity, and Scenario 7 for audit integrity. | [Test output](part3-test-output.txt) |
| 4:20 | Discuss the external key file, metadata exposure, retained downloads, and whole-database rollback. | [Threat model and key design](part5-technical-design.md) |

```powershell
.\.venv\Scripts\python.exe -u -m unittest discover -s tests -v
```

The test runner creates fresh keys, accounts, and databases. The demo uses fabricated content. The decision to revoke affects future authorization, and a file previously downloaded to Bob’s device remains there.
