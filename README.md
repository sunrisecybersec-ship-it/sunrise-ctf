# Sunrise Cybersecurity CTF Exam Platform

A Flask/Docker exam application with one instructor/admin portal, student PIN login, level-based access, a visual question editor, and final score/pass-fail reporting.

## Features

- **One website can serve both levels.** Set `LEVEL=both` in the environment. Students assigned to one level go straight into it; students assigned to both choose a level after signing in.
- Student accounts have individual allowed-level permissions (`level1`, `level2`, or both).
- Flag, short-text, single-choice MCQ, multiple-choice MCQ, and true/false question types.
- Admin question editor uses ordinary option fields and “Correct” checkboxes/radios—no JSON editing is needed.
- Add as many questions as needed. Each question has a level, title, instructions, type, points, and Published/Draft status.
- Per-question answer saving never reveals whether an answer is right or wrong.
- At final submission, answers are graded server-side. The student sees score, percentage, and PASS/FAIL. Passing threshold is 70%.
- Exam time limits are configurable independently with `LEVEL1_DURATION_MINUTES` and `LEVEL2_DURATION_MINUTES`.
- Staff roles, student PINs, audit log, question bank export, and final results CSV are retained.
- `/health` and `/healthz` provide health checks.

## Deploying one website on Render

1. Push the updated project files to the existing GitHub repository.
2. In Render, open the existing `sunrise-ctf` Web Service. Keep the existing service rather than creating a second service.
3. In **Environment**, set `LEVEL` to `both` (lowercase).
4. Keep `SECRET_KEY` and `ADMIN_PASSWORD` set as private Render environment variables. Do not commit secrets or share screenshots showing them.
5. If a Health Check Path is configured, use `/healthz`.
6. Commit the code changes to GitHub and wait for Render to redeploy. The public URL should remain the same.
7. Test admin login, a Level-1-only student, a Level-2-only student, and a student assigned to both levels.

The Dockerfile uses Gunicorn and binds to Render's `PORT` environment variable.

## Important free-hosting limitation

Render's free web services do not provide persistent disks and can spin down when idle. The default SQLite database lives at `/data/exam.db` inside the container. It is suitable for a disposable demo, but data may be lost when Render replaces the container. Do not use this exact free-storage setup for real exam records without moving to persistent storage/a managed database and arranging backups. Re-deployments may also reset local student accounts if the filesystem is replaced.

## Local Docker setup

The existing `docker-compose.yml` still runs two local portals (`http://localhost:8001` and `http://localhost:8002`) against a shared named volume. The two services set `LEVEL=level1` and `LEVEL=level2` respectively. For a single local service with both levels, run with `LEVEL=both` and map the chosen port.

1. Install Docker Engine / Docker Desktop and Python.
2. Run `python setup.py` to create a local `.env` file. Save the generated admin password securely.
3. Run `docker compose up --build -d`.
4. Visit `http://localhost:8001/health` and `http://localhost:8002/health`.
5. Open `http://localhost:8001/admin/login` and create test candidates.

## Question management

Open **Manage question bank** from the admin dashboard. Choose Level 1 or Level 2, fill in the question details, and for MCQs add each option in its own field and mark the correct option(s). Students only receive the question and option labels; the expected answer remains server-side.

Questions should be finalized before a real exam starts. Editing or deleting questions during an active exam can affect the final score calculation.

## Security notes

- Keep `.env`, database files, secret keys, admin passwords, PINs, and answer keys out of public GitHub repositories.
- Use unique secrets; never paste them into chat or screenshots.
- The free service may sleep after inactivity and has limited resources. This package is intended for testing/demo use until persistent storage, backups, and availability requirements are addressed.
