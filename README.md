# Sunrise CTF Exam Platform — Admin Question Bank Edition

This package runs two separate student portals backed by one SQLite database:

- **Level 1:** `http://localhost:8001`
- **Level 2:** `http://localhost:8002`
- **Instructor login:** `http://localhost:8001/admin/login`
- **Question bank manager:** `http://localhost:8001/admin/questions` after instructor login

## What the admin panel can do

- Add new questions to either level.
- Edit any existing question's title, instructions, topic, type, accepted answer, points, and active/draft status.
- Delete questions.
- Filter the question bank by level.
- Manage student candidate accounts and issue individual PINs.
- View candidate scores and export results to CSV.
- Download the **current** answer key and question bank backup as JSON from authenticated admin-only links.
- Changes are stored in SQLite and persist across container restarts. Both level portals use the same database.

## Supported answer formats

1. **Flag-based:** student enters a flag such as `SUNRISE{example}`. Matching trims outer whitespace and ignores letter case.
2. **Short text:** enter one or more accepted answers, one per line. Matching trims whitespace and ignores letter case.
3. **Single-choice MCQ:** student chooses one option. Provide options JSON and set the correct answer to one option's `value`.
4. **Multiple-choice MCQ:** student checks all correct options. Set the answer to comma-separated option values, such as `A,C`.
5. **True / False:** student selects True or False. Set the answer to `true` or `false`.

Example options JSON for an MCQ:

```json
[
  {"value": "A", "label": "Option A"},
  {"value": "B", "label": "Option B"},
  {"value": "C", "label": "Option C"},
  {"value": "D", "label": "Option D"}
]
```

The student API never returns the expected answer. Correct submissions turn green; incorrect submissions turn red. Points are awarded once per question. The timer starts when the student first loads the challenge list.

## First-time setup

Prerequisites: Docker Engine and Docker Compose plugin.

1. Extract this ZIP into a private folder on the exam host.
2. Open a terminal in that folder.
3. Run `python setup.py`. Save the instructor password printed once. It creates a private `.env` file.
4. Start the services:

   ```bash
   docker compose up --build -d
   ```

5. Verify the services:

   - `http://localhost:8001/health`
   - `http://localhost:8002/health`

   Each should return JSON with `"status":"ok"`.

6. Open `http://localhost:8001/admin/login`, sign in with the instructor password, and create a test candidate.
7. Open **Manage question bank**. Add/edit a test question, then verify it appears on the appropriate student portal.
8. Test one correct and one incorrect answer using a dedicated test candidate before real students are enrolled.

The `.env` file contains secrets and must remain private. Do not commit it to source control or share it with students.

## Classroom LAN access

For safety, Docker binds to `127.0.0.1` by default, which only allows access from the exam host. If students need access from classroom devices, change the two `ports` mappings in `docker-compose.yml` from `127.0.0.1:8001:8001` and `127.0.0.1:8002:8002` to `8001:8001` and `8002:8002`, then restrict inbound traffic with the host firewall to the classroom subnet. For a shared network, configure HTTPS via a reverse proxy and set `COOKIE_SECURE=1` in `.env`. Do not expose this directly to the public internet.

## Editing rules

- Do not change questions while students are actively taking the exam; changes apply immediately to both portals.
- Export the current question bank and answer key before a major edit.
- Back up the SQLite database before and after an exam. The database is stored in the Docker named volume `examdata`.
- If you change a question's answer or points, historical solved status/points may need review. Finalize the question bank before each exam cohort.
- Candidate PINs are displayed only at creation time. Deliver them privately.

## Backup and results

- Results CSV: **Export results CSV** in the admin dashboard.
- Current answer key JSON: **Download current answer key** (admin only).
- Question bank JSON backup: **Export question bank** (admin only).
- Stop containers without deleting saved data: `docker compose down`.
- Do not run `docker compose down -v` unless you intend to delete the database volume.

## Validation status and limits

The package includes the original 30 seeded questions per level, dynamic question management, five answer formats, server-side checking, candidate PINs, persistent SQLite storage, and health endpoints. The app's Python syntax and embedded JavaScript syntax have been checked in the build environment. This environment did not have Flask or Docker available, so the complete HTTP workflow, container startup, and end-to-end exam process could not be executed here. Before a live exam, complete the checklist below on the actual exam host.

## Mandatory live acceptance checklist

- [ ] Both health endpoints return `status: ok`.
- [ ] Instructor login works and the admin panel is not accessible when logged out.
- [ ] Create a test candidate and verify login works on both portals.
- [ ] Add a test flag question, answer it correctly, and see green feedback.
- [ ] Submit a wrong answer and see red feedback with no points awarded.
- [ ] Add and test each desired question type: short text, single MCQ, multi-select MCQ, and True/False.
- [ ] Edit a question and confirm the change appears on the correct portal.
- [ ] Deactivate a question and confirm students no longer see it; reactivate it afterward if needed.
- [ ] Confirm a second candidate cannot see the first candidate's progress.
- [ ] Confirm score persists after logout/relogin and duplicate solves do not award extra points.
- [ ] Confirm timers expire and block further submissions.
- [ ] Confirm current answer-key and question-bank downloads require admin login.
- [ ] Test classroom LAN access from student devices, firewall rules, and HTTPS before sharing links.
- [ ] Back up the database and verify that the backup can be restored.
- [ ] Confirm Level 2 has real, isolated vulnerable targets for every challenge if you intend to assess hands-on exploitation. The included Level 2 questions are evidence/scenario challenges; this app does not itself deploy vulnerable targets.

This is an instructor-run starter platform, not a security-certified examination product. Do not describe it as fully production-certified until the live acceptance checklist and any required security/load testing have passed.


## Four-role access control (added in this build)

- **Super Admin**: manage staff accounts/roles, students, questions, results, answer keys, and exam settings permissions. The last active Super Admin cannot be demoted or disabled.
- **Exam Admin**: create/disable student accounts, manage both question banks, view/export results, and access answer keys.
- **Instructor**: view results dashboard and export results only. (Student-to-instructor assignment filtering is not implemented in this starter release.)
- **Student**: candidate ID + PIN account; can attempt assigned level portal only. Super Admin can disable/enable student accounts.

### First staff login

The bootstrap staff account username is `admin`. Use the password printed by `python setup.py` (the same password previously called the instructor password). Staff login is at `/admin/login`. The Super Admin can open **Manage users & roles** from the dashboard, create staff accounts, assign one of the three staff roles, and disable/enable accounts. Student accounts are created separately from the dashboard and appear as the fourth role in the role manager.

Role assignments are enforced server-side on protected routes. Changes to staff roles, staff creation, login/logout, and student account status are recorded in the audit log. Generated staff passwords are shown only at account creation; arrange a secure handoff and implement a password-change workflow before production use.

## Per-student exam-level access

The student creation form lets staff select Level 1 and/or Level 2. To change an existing student's access, open **Admin Dashboard → Manage users & roles → Student accounts**, select the allowed levels, and click **Save access**. At least one level must be selected. The server enforces the selection at login and on authenticated exam API requests. Existing candidates are migrated with both levels enabled so they are not unexpectedly locked out.

When running with Docker, both level portals must use the same `/data/exam.db` on the same named volume. For a single-container Windows setup, run one container for Level 1 on host port 5000 and a second for Level 2 on host port 5001, both mounting the same `sunrise-ctf-data` volume and using the same `SECRET_KEY` and `ADMIN_PASSWORD` environment values. Example after building the updated image:

```powershell
docker run -d --name sunrise-ctf-app -p 5000:8001 -e LEVEL=level1 -e PORT=8001 -e SECRET_KEY="$env:SECRET_KEY" -e ADMIN_PASSWORD="$env:ADMIN_PASSWORD" -v sunrise-ctf-data:/data sunrise-ctf
docker run -d --name sunrise-ctf-level2 -p 5001:8002 -e LEVEL=level2 -e PORT=8002 -e SECRET_KEY="$env:SECRET_KEY" -e ADMIN_PASSWORD="$env:ADMIN_PASSWORD" -v sunrise-ctf-data:/data sunrise-ctf
```

Level 1 URL: `http://localhost:5000`; Level 2 URL: `http://localhost:5001`. Do not run both portals with separate database volumes or student access settings will not be shared.

### Administering student access and PINs

Open **Manage users & roles** from the staff dashboard. In **Student accounts**, select Level 1 and/or Level 2 and press **Save access** to modify a student's assigned levels. You can do this repeatedly after the account has been created. To set a chosen student PIN, enter a new value (4–80 characters) and select **Reset PIN**. Only the salted password hash is stored. Enable/Disable suspends or reactivates the account. These operations are audit-logged. Share student PINs through a private channel.

**Password security:** never put real passwords in source files or ZIPs. If a staff password has been pasted into a chat or shared transcript, treat it as exposed and rotate it. The `ADMIN_PASSWORD` environment variable is only used to bootstrap the first Super Admin when the staff table is empty; changing that environment variable later does not change an existing account's stored password. Use a proper password-reset workflow for staff accounts before production deployment.
