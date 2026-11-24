import argparse
import getpass
import sqlite3

from werkzeug.security import generate_password_hash

from . import PASSWORD_METHOD, USERNAME, create_app, paths
from .storage import AuditIntegrityError, create_keys, initialize, load_keys, record, transaction, verify_audit


def prompt_password():
    password = getpass.getpass("Password: ")
    if not 12 <= len(password) <= 256:
        raise ValueError("Password length must be between 12 and 256 characters.")
    if password != getpass.getpass("Confirm password: "):
        raise ValueError("Passwords do not match.")
    return generate_password_hash(password, method=PASSWORD_METHOD)


def main():
    parser = argparse.ArgumentParser(description="Secure Document Management System")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init", help="Create the local database and key file")
    subcommands.add_parser("verify-audit", help="Authenticate the complete audit history")
    serve = subcommands.add_parser("serve", help="Run the HTTP demonstration on loopback")
    serve.add_argument("--port", type=int, default=5000)
    create = subcommands.add_parser("create-user", help="Provision an account")
    create.add_argument("username")
    create.add_argument("--role", choices=("member", "admin"), default="member")
    for command in ("reset-password", "disable-user", "enable-user"):
        subcommands.add_parser(command).add_argument("username")
    args = parser.parse_args()
    db_path, key_path = paths()
    if args.command == "init":
        if db_path == key_path:
            raise ValueError("Choose distinct paths for the database and key file.")
        if db_path.exists() and not key_path.exists():
            raise ValueError("Restore the original key file before initializing an existing database.")
        create_keys(key_path)
        initialize(db_path, load_keys(key_path)["audit"])
        print(f"Database ready at {db_path}")
        return
    if args.command == "serve":
        create_app({"SESSION_COOKIE_SECURE": False}).run(host="127.0.0.1", port=args.port, debug=False)
        return
    if not db_path.is_file():
        raise ValueError("Database is missing. Run python -m sdms init.")
    key = load_keys(key_path)["audit"]
    if args.command == "verify-audit":
        with transaction(db_path) as db:
            count = verify_audit(db, key)
        print(f"Verified {count} audit events.")
        return

    username = args.username.strip().lower()
    if not USERNAME.fullmatch(username):
        raise ValueError("Use 3–40 letters, digits, underscores, periods or hyphens for the username.")
    password_hash = None
    if args.command in ("create-user", "reset-password"):
        password_hash = prompt_password()
    with transaction(db_path) as db:
        account = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if args.command == "create-user":
            if account is not None:
                raise ValueError("That username is already in use.")
            user_id = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                                 (username, password_hash, args.role)).lastrowid
            log_detail = f"user={user_id} role={args.role}"
        else:
            if account is None:
                raise ValueError("Account unavailable.")
            user_id = account["id"]
            if args.command == "reset-password":
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            else:
                db.execute("UPDATE users SET active = ? WHERE id = ?", (args.command == "enable-user", user_id))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            log_detail = f"user={user_id}"
        record(db, key, None, args.command.replace("-", "_"), detail=log_detail)
    print(f"{args.command} completed for {username}.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, AuditIntegrityError) as error:
        raise SystemExit(str(error)) from error
