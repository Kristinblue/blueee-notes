"""Account enrolment and isolated vault grants for Blueee Notes."""
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time

NAME = re.compile(r"[a-z0-9][a-z0-9_-]{2,39}")
PROOF = re.compile(r"[A-Za-z0-9+/]{43}=")
WRAPPED_KEY = re.compile(r"[A-Za-z0-9+/]{22}==\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{64}")
TOKEN_DAYS = 90
AUTH_WORKERS = threading.BoundedSemaphore(4)

SCHEMA = """
CREATE TABLE IF NOT EXISTS account_credentials (
    name TEXT PRIMARY KEY,
    verifier TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS account_vaults (
    account TEXT REFERENCES account_credentials(name),
    slug TEXT, vault TEXT UNIQUE NOT NULL REFERENCES vaults(name),
    wrapped_key TEXT NOT NULL, PRIMARY KEY(account, slug)
);
CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash TEXT PRIMARY KEY, vault TEXT NOT NULL REFERENCES account_vaults(vault),
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS server_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS plugin_lists (
    vault TEXT PRIMARY KEY REFERENCES vaults(name), encrypted_list TEXT NOT NULL
);
"""


def password_hash(value, salt=None):
    salt = salt or secrets.token_bytes(16)
    result = hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + ":" + result.hex()


def matches(value, stored):
    return hmac.compare_digest(password_hash(value, bytes.fromhex(stored.split(":")[0])), stored)


def set_invite(db, code=None):
    if code is None:
        code = getpass.getpass("注册口令（至少 12 个字符，输入时隐藏）: ")
        if code != getpass.getpass("再输入一次: "):
            raise SystemExit("两次输入不同。")
    if not 12 <= len(code) <= 256:
        raise SystemExit("口令长度无效或两次输入不同。")
    db.execute("""INSERT INTO server_settings VALUES ('registration_invite', ?)
                  ON CONFLICT(name) DO UPDATE SET value=excluded.value""", (password_hash(code),))


def connect(database, path, data, token_hash):
    if not isinstance(data, dict):
        return 400, "invalid_request"
    mode = data.get("mode")
    name, slug, proof = (data.get(field) for field in ("account", "vault", "proof"))
    if mode not in ("register", "login", "create") or not all(
        isinstance(value, str) and pattern.fullmatch(value)
        for value, pattern in ((name, NAME), (slug, NAME), (proof, PROOF))
    ):
        return 400, "invalid_request"
    wrapped = data.get("wrappedKey")
    invite = data.get("invite", "")
    if mode != "login" and (not isinstance(wrapped, str) or not WRAPPED_KEY.fullmatch(wrapped)):
        return 400, "invalid_request"
    if mode == "register" and (not isinstance(invite, str) or not 1 <= len(invite) <= 256):
        return 400, "invalid_request"
    if not AUTH_WORKERS.acquire(blocking=False):
        return 429, "busy"
    try:
        return connect_account(database, path, mode, name, slug, proof, wrapped, invite, token_hash)
    finally:
        AUTH_WORKERS.release()


def connect_account(database, path, mode, name, slug, proof, wrapped, invite, token_hash):
    with database(path) as db:
        if mode == "register":
            row = db.execute("SELECT value FROM server_settings WHERE name='registration_invite'").fetchone()
        else:
            row = db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone()
    if mode == "register":
        if not row:
            return 403, "registration_closed"
        if not matches(invite, row[0]):
            return 403, "invite_invalid"
        verifier = password_hash(proof)
    elif not row or row[1] or not matches(proof, row[0]):
        return 401, "login_invalid"

    now = int(time.time())
    token = secrets.token_urlsafe(32)
    try:
        with database(path) as db:
            db.execute("BEGIN IMMEDIATE")
            if mode == "register":
                if db.execute("SELECT value FROM server_settings WHERE name='registration_invite'").fetchone() != row:
                    return 403, "invite_invalid"
                db.execute("INSERT INTO account_credentials(name,verifier) VALUES (?,?)", (name, verifier))
            elif db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone() != row:
                return 401, "login_invalid"
            existing = db.execute("SELECT vault,wrapped_key FROM account_vaults WHERE account=? AND slug=?",
                                  (name, slug)).fetchone()
            if mode == "login":
                if not existing:
                    return 404, "vault_missing"
                vault, wrapped = existing
            else:
                if existing:
                    return 409, "vault_exists"
                vault = "account-" + secrets.token_hex(16)
                db.execute("INSERT INTO vaults VALUES (?)", (vault,))
                db.execute("INSERT INTO account_vaults VALUES (?,?,?,?)", (name, slug, vault, wrapped))
            db.execute("DELETE FROM account_sessions WHERE expires<=?", (now,))
            db.execute("INSERT INTO account_sessions VALUES (?,?,?)",
                       (token_hash(token), vault, now + TOKEN_DAYS * 86400))
    except sqlite3.IntegrityError:
        if mode != "register":
            raise
        return 409, "account_exists"
    return 200, {"token": token, "wrappedKey": wrapped}
