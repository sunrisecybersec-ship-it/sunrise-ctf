# Level access and single-site deployment

- Render single-site mode is enabled with `LEVEL=both`.
- Student login checks `allowed_levels`; students with one allowed level go directly to it, while students assigned to both choose a level after login.
- The same admin panel manages students and question banks for Level 1 and Level 2.
- Local Docker Compose retains separate Level 1 and Level 2 URLs while using the same named SQLite volume.
- Per-question submissions save answers without revealing correctness. Final submission grades the stored answers and records score, percentage, and PASS/FAIL at the 70% threshold.
- Free Render services do not provide persistent disks; the default SQLite database can be lost on container replacement. Use persistent storage before real exams.
