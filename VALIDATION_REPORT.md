# Validation report — four-role access control build

## Checks completed in this environment
- Python syntax compilation passed for `app.py` and `setup.py`.
- Jinja template compilation passed for login, dashboard, question manager, exam/student pages, and role-management page.
- Database initialization smoke test passed using a minimal Flask shim: the initial `admin` account is bootstrapped as `super_admin`, and both level banks seed 30 records each.
- The Dockerfile now includes `roles.html`.
- Added automated tests for Super Admin login/role manager access and Instructor permission denial on question management.

## Not completed here
- Full Flask integration tests could not run because Flask is not installed in this build environment and network access to install it is unavailable.
- Docker image build and multi-container run could not be executed because Docker is unavailable in this environment.
- No independent security audit or live network deployment test has been performed.

## Roles implemented
- Super Admin: user/role management, student management, question management, results, answer key.
- Exam Admin: student management, question management, results, answer key.
- Instructor: results view/export only. Instructor-specific student assignment filtering is not implemented in this starter build.
- Student: existing candidate ID/PIN portal account; can be disabled/enabled by Super Admin.

The package should be built and acceptance-tested in the target Docker environment before live exams.
