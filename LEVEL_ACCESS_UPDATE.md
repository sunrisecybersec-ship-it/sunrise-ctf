# Per-student Level Access Update

- Student creation now offers Level 1 and Level 2 checkboxes (Level 1 selected by default).
- Super Admin can change existing students' allowed levels from **Manage users & roles → Student accounts**.
- Server-side checks deny login and exam API access to a level not assigned to that candidate.
- Existing databases migrate automatically; existing candidates retain both levels until edited.
- Both level services must share the same `/data/exam.db` and Docker named volume.

Validation performed: Python syntax compilation and Jinja template syntax checks passed. Full Flask integration tests were not run in this environment because Flask is not installed here.

## Student PIN reset and access changes

From the authorized staff dashboard, open **Manage users & roles**. In the Student accounts table:

- Tick Level 1, Level 2, or both and click **Save access** to change access at any time.
- Enter a new PIN (4–80 characters) and click **Reset PIN**. The database stores a salted PBKDF2 hash, not the PIN in plain text.
- Use Enable/Disable to suspend or reactivate a student.

PIN resets and access/status changes are recorded in the audit log. Share PINs with students privately. Students should sign in with their candidate ID and PIN.
