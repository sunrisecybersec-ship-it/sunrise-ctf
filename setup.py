from pathlib import Path
import secrets, sys

env_path = Path(".env")
if env_path.exists() and "--reset" not in sys.argv:
    print(".env already exists; leaving secrets unchanged.")
    print("If you need new secrets, back up results first and run: python setup.py --reset")
    raise SystemExit(0)
admin_password = secrets.token_urlsafe(18)
secret_key = secrets.token_urlsafe(48)
env_path.write_text(
    f"SECRET_KEY={secret_key}\n"
    f"ADMIN_PASSWORD={admin_password}\n"
    "COOKIE_SECURE=0\n"
    "LEVEL1_DURATION_MINUTES=60\n"
    "LEVEL2_DURATION_MINUTES=120\n",
    encoding="utf-8"
)
try:
    env_path.chmod(0o600)
except OSError:
    pass
print("Created private .env file.")
print("Super Admin username: admin")
print("Super Admin password (save securely; shown once here):")
print(admin_password)
print("Default exam durations: Level 1 = 60 minutes; Level 2 = 120 minutes.")
print("Local-only binding is enabled by default. Read README.md before exposing this to a classroom network.")
