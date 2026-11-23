"""Account enrolment and isolated vault grants for Blueee Notes."""
import getpass
import hashlib
import hmac
import re
import secrets
import json
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
import threading
import time

NAME = re.compile(r"[a-z0-9][a-z0-9_-]{2,39}")
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
PROOF = re.compile(r"[A-Za-z0-9+/]{43}=")
WRAPPED_KEY = re.compile(r"[A-Za-z0-9+/]{22}==\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{64}")
TOKEN_DAYS = 90
AUTH_WORKERS = threading.BoundedSemaphore(4)

SCHEMA = """
CREATE TABLE IF NOT EXISTS account_credentials (
    name TEXT PRIMARY KEY,
    verifier TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS registrations (
    name TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, state TEXT NOT NULL,
    verifier TEXT, slug TEXT, wrapped_key TEXT, code_hash TEXT,
    expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL
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


def mail_path(path):
    return Path(path).with_name("smtp.json")


def send_code(path, recipient, code):
    config = json.loads(mail_path(path).read_text(encoding="utf-8"))
    message = EmailMessage()
    message["From"], message["To"] = config["address"], recipient
    message["Subject"] = "Blueee Notes 邮箱验证码"
    message.set_content(f"你的 Blueee Notes 验证码是 {code}。验证码在 15 分钟内有效。")
    context = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL if config["port"] == 465 else smtplib.SMTP
    options = {"context": context} if config["port"] == 465 else {}
    with smtp(config["host"], config["port"], timeout=12, **options) as connection:
        if config["port"] != 465:
            connection.starttls(context=context)
        connection.login(config["username"], config["password"])
        connection.send_message(message)


def connect(database, path, data, token_hash):
    if not isinstance(data, dict):
        return 400, "invalid_request"
    mode = data.get("mode")
    name, slug, proof = (data.get(field) for field in ("account", "vault", "proof"))
    if mode not in ("register", "verify", "login", "create") or not all(
        isinstance(value, str) and pattern.fullmatch(value)
        for value, pattern in ((name, NAME), (slug, NAME), (proof, PROOF))
    ):
        return 400, "invalid_request"
    wrapped = data.get("wrappedKey")
    if mode in ("register", "create") and (not isinstance(wrapped, str) or not WRAPPED_KEY.fullmatch(wrapped)):
        return 400, "invalid_request"
    if not AUTH_WORKERS.acquire(blocking=False):
        return 429, "busy"
    try:
        if mode in ("register", "verify"):
            return enrol(database, path, data, name, slug, proof, wrapped)
        return connect_account(database, path, mode, name, slug, proof, wrapped, token_hash)
    finally:
        AUTH_WORKERS.release()


def enrol(database, path, data, name, slug, proof, wrapped):
    email = data.get("email")
    if not isinstance(email, str) or len(email) > 254 or not EMAIL.fullmatch(email):
        return 400, "email_invalid"
    if data["mode"] == "verify":
        return verify_email(database, path, name, email, proof, data.get("code"))
    invite = data.get("invite")
    if not isinstance(invite, str) or not 1 <= len(invite) <= 256:
        return 400, "invalid_request"
    with database(path) as db:
        setting = db.execute("SELECT value FROM server_settings WHERE name='registration_invite'").fetchone()
    if not setting:
        return 403, "registration_closed"
    if not matches(invite, setting[0]):
        return 403, "invite_invalid"

    now = int(time.time())
    code = f"{secrets.randbelow(1000000):06}"
    verifier = password_hash(proof)
    code_hash = password_hash(code)
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT value FROM server_settings WHERE name='registration_invite'").fetchone() != setting:
            return 403, "invite_invalid"
        previous = db.execute("""
            SELECT name,state,verifier,sent FROM registrations WHERE email=?
        """, (email,)).fetchone()
        if db.execute("SELECT 1 FROM account_credentials WHERE name=?", (name,)).fetchone():
            return 409, "account_exists"
        if previous and previous[1] != "unverified":
            if previous[0] == name and previous[1] == "pending" and matches(proof, previous[2]):
                return 202, {"status": "approval_pending"}
            return 409, "registration_conflict"
        if previous and previous[3] > now - 60:
            return 429, "resend_wait"
        if db.execute("SELECT count(*) FROM registrations WHERE sent>?", (now - 60,)).fetchone()[0] >= 12:
            return 429, "resend_wait"
        db.execute("DELETE FROM registrations WHERE state='unverified' AND expires<=?", (now,))
        if db.execute("SELECT 1 FROM registrations WHERE name=? AND email<>?", (name, email)).fetchone():
            return 409, "registration_conflict"
        db.execute("""
            INSERT INTO registrations(name,email,state,verifier,slug,wrapped_key,code_hash,expires,sent)
            VALUES (?,?,'unverified',?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name,
              verifier=excluded.verifier,slug=excluded.slug,wrapped_key=excluded.wrapped_key,
              code_hash=excluded.code_hash,expires=excluded.expires,sent=excluded.sent,attempts=0
        """, (name, email, verifier, slug, wrapped, code_hash, now + 900, now))
    try:
        send_code(path, email, code)
    except (OSError, KeyError, ValueError, smtplib.SMTPException):
        with database(path) as db:
            db.execute("DELETE FROM registrations WHERE email=? AND state='unverified' AND code_hash=?",
                       (email, code_hash))
        return 503, "mail_unavailable"
    return 202, {"status": "verification_required"}


def verify_email(database, path, name, email, proof, code):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return 400, "code_invalid"
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""
            SELECT state,verifier,code_hash,expires,attempts FROM registrations WHERE name=? AND email=?
        """, (name, email)).fetchone()
        if not row or row[0] == "approved" or not matches(proof, row[1]):
            return 403, "code_invalid"
        if row[0] == "pending":
            return 202, {"status": "approval_pending"}
        if row[3] <= int(time.time()) or row[4] >= 5:
            return 403, "code_expired"
        if not matches(code, row[2]):
            db.execute("UPDATE registrations SET attempts=attempts+1 WHERE name=?", (name,))
            return 403, "code_invalid"
        db.execute("UPDATE registrations SET state='pending',code_hash=NULL WHERE name=?", (name,))
    return 202, {"status": "approval_pending"}


def decide(db, name, approve):
    db.execute("BEGIN IMMEDIATE")
    row = db.execute("SELECT verifier,slug,wrapped_key FROM registrations WHERE name=? AND state='pending'",
                     (name,)).fetchone()
    if not row:
        raise SystemExit("找不到已验证邮箱的待审批申请。")
    if approve:
        verifier, slug, wrapped = row
        db.execute("INSERT INTO account_credentials(name,verifier) VALUES (?,?)", (name, verifier))
        add_vault(db, name, slug, wrapped)
        db.execute("""UPDATE registrations SET state='approved',verifier=NULL,slug=NULL,wrapped_key=NULL
                      WHERE name=?""", (name,))
    else:
        db.execute("DELETE FROM registrations WHERE name=?", (name,))


def add_vault(db, name, slug, wrapped):
    vault = "account-" + secrets.token_hex(16)
    db.execute("INSERT INTO vaults VALUES (?)", (vault,))
    db.execute("INSERT INTO account_vaults VALUES (?,?,?,?)", (name, slug, vault, wrapped))
    return vault


def connect_account(database, path, mode, name, slug, proof, wrapped, token_hash):
    with database(path) as db:
        row = db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone()
        pending = db.execute("SELECT verifier FROM registrations WHERE name=? AND state='pending'",
                             (name,)).fetchone()
    if not row or row[1] or not matches(proof, row[0]):
        if pending and matches(proof, pending[0]):
            return 403, "approval_pending"
        return 401, "login_invalid"
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone() != row:
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
            vault = add_vault(db, name, slug, wrapped)
        db.execute("DELETE FROM account_sessions WHERE expires<=?", (now,))
        db.execute("INSERT INTO account_sessions VALUES (?,?,?)",
                   (token_hash(token), vault, now + TOKEN_DAYS * 86400))
    return 200, {"token": token, "wrappedKey": wrapped}
