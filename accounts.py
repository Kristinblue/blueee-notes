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
from html import escape
from pathlib import Path
import threading
import time

NAME = re.compile(r"[a-z0-9][a-z0-9_-]{2,39}")
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
PROOF = re.compile(r"[A-Za-z0-9+/]{43}=")
WRAPPED_KEY = re.compile(r"(?:v2\.)?[A-Za-z0-9+/]{22}==\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{64}")
TOKEN_DAYS = 90
INVITE_TICKET = re.compile(r"([0-9]{1,12})\.([A-Za-z0-9_-]{22})\.([a-f0-9]{64})")
INVITE_TTL = 900
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
CREATE TABLE IF NOT EXISTS account_devices (
    account TEXT NOT NULL, id TEXT NOT NULL, label TEXT NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY(account,id)
);
CREATE TABLE IF NOT EXISTS device_codes (
    account TEXT NOT NULL, device TEXT NOT NULL, code_hash TEXT NOT NULL,
    expires INTEGER NOT NULL, sent INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(account,device)
);
CREATE TABLE IF NOT EXISTS password_codes (
    account TEXT PRIMARY KEY, device TEXT NOT NULL, code_hash TEXT NOT NULL,
    expires INTEGER NOT NULL, sent INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_sessions (
    token_hash TEXT PRIMARY KEY REFERENCES account_sessions(token_hash) ON DELETE CASCADE,
    account TEXT NOT NULL, device TEXT NOT NULL
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
    db.execute("DELETE FROM server_settings WHERE name='registration_closed'")


def mail_path(path):
    return Path(path).with_name("smtp.json")


def send_code(path, recipient, code, purpose="register"):
    if purpose != "register":
        return send_security_code(path, recipient, code, purpose)
    config = json.loads(mail_path(path).read_text(encoding="utf-8"))
    message = EmailMessage()
    message["From"], message["To"] = config["address"], recipient
    message["Subject"] = "Blueee Notes 邮箱验证码"
    message.set_content(
        "欢迎来到Blueee的小插件\n\n"
        "这是我做的一个笔记同步小插件，方便你在电脑、手机和平板上接着写。"
        "后续功能也会慢慢加上。\n\n"
        f"邮箱验证码：{code}\n有效期：15 分钟\n\n"
        "请回到 Obsidian 的 Blueee Notes 设置输入验证码。"
        "邮箱验证通过后，等作者审核你的账号申请，即可开始同步。"
    )
    safe_code = escape(code)
    message.add_alternative(f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;background:#f4f1f9;color:#272338;font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f1f9">
<tr><td align="center" style="padding:28px 12px">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"
 style="max-width:520px;background:#ffffff;border:1px solid #e9e1f2;border-radius:16px">
<tr><td style="padding:28px 24px 4px;font-size:15px;font-weight:bold;color:#6640a6">Blueee Notes</td></tr>
<tr><td style="padding:0 24px;font-size:16px;line-height:1.7">
<h1 style="margin:8px 0 12px;color:#272338;font-size:26px;line-height:1.35">欢迎来到Blueee的小插件</h1>
<p style="margin:0 0 20px">这是我做的一个笔记同步小插件，方便你在电脑、手机和平板上接着写。后续功能也会慢慢加上。</p>
</td></tr>
<tr><td style="padding:0 24px">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"
 style="background:#f0e9fa;border:1px solid #e6d9f5;border-radius:12px">
<tr><td align="center" style="padding:16px 6px 0;font-size:14px;font-weight:bold;color:#54337b">邮箱验证码</td></tr>
<tr><td align="center" style="padding:3px 4px;color:#301a51;font-size:38px;font-weight:bold;
 font-family:Consolas,monospace;letter-spacing:5px;line-height:1.3">{safe_code}</td></tr>
<tr><td align="center" style="padding:3px 8px 16px;font-size:13px;color:#54337b">15 分钟内有效</td></tr>
</table>
</td></tr>
<tr><td style="padding:20px 24px 28px;font-size:15px;line-height:1.7;color:#433951">
<p style="margin:0">回到 Obsidian 的 Blueee Notes 设置输入验证码。邮箱验证通过后，等作者审核你的账号申请，就可以开始同步啦！</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""", subtype="html")
    deliver(config, message)


def send_security_code(path, recipient, code, purpose):
    config = json.loads(mail_path(path).read_text(encoding="utf-8"))
    message = EmailMessage()
    message["From"], message["To"] = config["address"], recipient
    action = "修改密码" if purpose == "password" else "新设备登录"
    message["Subject"] = f"Blueee Notes {action}验证码"
    message.set_content(f"你正在进行{action}。请在 Obsidian 输入验证码：{code}。验证码 15 分钟内有效。")
    deliver(config, message)


def deliver(config, message):
    context = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL if config["port"] == 465 else smtplib.SMTP
    options = {"context": context} if config["port"] == 465 else {}
    with smtp(config["host"], config["port"], timeout=12, **options) as connection:
        if config["port"] != 465:
            connection.starttls(context=context)
        connection.login(config["username"], config["password"])
        connection.send_message(message)


def invite_setting(db):
    row = db.execute("SELECT value FROM server_settings WHERE name='registration_invite'").fetchone()
    return row[0] if row else None


def invite_signature(setting, body):
    return hmac.new(setting.encode(), ("blueee-registration:" + body).encode(), hashlib.sha256).hexdigest()


def valid_invite_ticket(setting, ticket):
    matched = INVITE_TICKET.fullmatch(ticket) if isinstance(ticket, str) else None
    if not matched:
        return False
    expiry, nonce, signature = matched.groups()
    now = int(time.time())
    return now < int(expiry) <= now + INVITE_TTL and hmac.compare_digest(
        signature, invite_signature(setting, expiry + "." + nonce)
    )


def check_invite(database, path, invite):
    if not isinstance(invite, str) or not 1 <= len(invite) <= 256:
        return 400, "invite_invalid"
    with database(path) as db:
        setting = invite_setting(db)
    if not setting:
        return 403, "registration_closed"
    if not AUTH_WORKERS.acquire(blocking=False):
        return 429, "busy"
    try:
        if not matches(invite, setting):
            return 403, "invite_invalid"
    finally:
        AUTH_WORKERS.release()
    body = str(int(time.time()) + INVITE_TTL) + "." + secrets.token_urlsafe(16)
    return 200, {"ticket": body + "." + invite_signature(setting, body)}


def connect(database, path, data, token_hash):
    if not isinstance(data, dict):
        return 400, "invalid_request"
    mode = data.get("mode")
    if mode == "check_invite":
        return check_invite(database, path, data.get("invite"))
    name, slug, proof = (data.get(field) for field in ("account", "vault", "proof"))
    if mode not in ("register", "verify", "login", "create") or not all(
        isinstance(value, str) and pattern.fullmatch(value)
        for value, pattern in ((name, NAME), (slug, NAME), (proof, PROOF))
    ):
        return 400, "invalid_request"
    wrapped = data.get("wrappedKey")
    if mode in ("register", "create") and (not isinstance(wrapped, str) or not WRAPPED_KEY.fullmatch(wrapped)):
        return 400, "invalid_request"
    with database(path) as db:
        setting = invite_setting(db)
    if not setting or not valid_invite_ticket(setting, data.get("ticket")):
        return 403, "invite_step_required"
    raw_device = data.get("device")
    if not isinstance(raw_device, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", raw_device):
        return 400, "device_required"
    device = hashlib.sha256(raw_device.encode()).hexdigest()
    label = data.get("deviceName")
    label = label.strip()[:60] if isinstance(label, str) else ""
    if not AUTH_WORKERS.acquire(blocking=False):
        return 429, "busy"
    try:
        if mode in ("register", "verify"):
            return enrol(database, path, data, name, slug, proof, wrapped, device, label)
        return connect_account(database, path, mode, name, slug, proof, wrapped, token_hash, device, label, data.get("code"))
    finally:
        AUTH_WORKERS.release()


def enrol(database, path, data, name, slug, proof, wrapped, device, label):
    email = data.get("email")
    if not isinstance(email, str) or len(email) > 254 or not EMAIL.fullmatch(email):
        return 400, "email_invalid"
    if data["mode"] == "verify":
        return verify_email(database, path, name, email, proof, data.get("code"), device, label)
    ticket = data.get("ticket")
    now = int(time.time())
    code = f"{secrets.randbelow(1000000):06}"
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        setting = invite_setting(db)
        if db.execute("SELECT 1 FROM server_settings WHERE name='registration_closed'").fetchone():
            return 403, "registration_closed"
        if not setting or not valid_invite_ticket(setting, ticket):
            return 403, "invite_step_required"
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
        verifier = password_hash(proof)
        code_hash = password_hash(code)
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


def verify_email(database, path, name, email, proof, code, device, label):
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
        trust_device(db, name, device, label)
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
        db.execute("DELETE FROM account_devices WHERE account=?", (name,))


def add_vault(db, name, slug, wrapped):
    vault = "account-" + secrets.token_hex(16)
    db.execute("INSERT INTO vaults VALUES (?)", (vault,))
    db.execute("INSERT INTO account_vaults VALUES (?,?,?,?)", (name, slug, vault, wrapped))
    return vault


def trust_device(db, account, device, label):
    now = int(time.time())
    db.execute("INSERT OR IGNORE INTO account_devices VALUES (?,?,?,?,?)",
               (account, device, label or "Obsidian", now, now))


def verify_device(database, path, name, device, label, code, verifier):
    now = int(time.time())
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone() != verifier:
            return 401, "login_invalid"
        if db.execute("SELECT 1 FROM account_devices WHERE account=? AND id=?", (name, device)).fetchone():
            return None
        row = db.execute("SELECT code_hash,expires,sent,attempts FROM device_codes WHERE account=? AND device=?",
                         (name, device)).fetchone()
        if code:
            if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code) or not row:
                return 403, "code_invalid"
            if row[1] <= now or row[3] >= 5:
                return 403, "code_expired"
            if not matches(code, row[0]):
                db.execute("UPDATE device_codes SET attempts=attempts+1 WHERE account=? AND device=?", (name, device))
                return 403, "code_invalid"
            trust_device(db, name, device, label)
            db.execute("DELETE FROM device_codes WHERE account=? AND device=?", (name, device))
            return None
        if row and row[1] > now and row[3] < 5:
            return 202, {"status": "device_verification_required"}
        email = db.execute("SELECT email FROM registrations WHERE name=? AND state='approved'", (name,)).fetchone()
        if not email:
            return 403, "email_invalid"
        if db.execute("SELECT 1 FROM device_codes WHERE account=? AND sent>?", (name, now-60)).fetchone():
            return 429, "resend_wait"
        generated = f"{secrets.randbelow(1000000):06}"
        digest = password_hash(generated)
        db.execute("DELETE FROM device_codes WHERE expires<=?", (now,))
        db.execute("""INSERT OR REPLACE INTO device_codes(account,device,code_hash,expires,sent)
                      VALUES (?,?,?,?,?)""", (name, device, digest, now+900, now))
    try:
        send_code(path, email[0], generated, "device")
    except (OSError, KeyError, ValueError, smtplib.SMTPException):
        with database(path) as db:
            db.execute("DELETE FROM device_codes WHERE account=? AND device=? AND code_hash=?", (name, device, digest))
        return 503, "mail_unavailable"
    return 202, {"status": "device_verification_required"}


def connect_account(database, path, mode, name, slug, proof, wrapped, token_hash, device, label, code):
    with database(path) as db:
        row = db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone()
        pending = db.execute("SELECT verifier FROM registrations WHERE name=? AND state='pending'",
                             (name,)).fetchone()
    if not row or row[1] or not matches(proof, row[0]):
        if pending and matches(proof, pending[0]):
            return 403, "approval_pending"
        return 401, "login_invalid"
    verification = verify_device(database, path, name, device, label, code, row)
    if verification:
        return verification
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT verifier,disabled FROM account_credentials WHERE name=?", (name,)).fetchone() != row:
            return 401, "login_invalid"
        if not db.execute("SELECT 1 FROM account_devices WHERE account=? AND id=?", (name, device)).fetchone():
            return 403, "device_required"
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
        db.execute("INSERT INTO device_sessions VALUES (?,?,?)", (token_hash(token), name, device))
        db.execute("UPDATE account_devices SET last_seen=? WHERE account=? AND id=?", (now, name, device))
    return 200, {"token": token, "wrappedKey": wrapped}


def change_password(database, path, identity, data):
    name, device = identity
    if not isinstance(data, dict):
        return 400, "invalid_request"
    old = data.get("oldProof")
    if not isinstance(old, str) or not PROOF.fullmatch(old):
        return 400, "invalid_request"
    now = int(time.time())
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT verifier FROM account_credentials WHERE name=? AND disabled=0", (name,)).fetchone()
        if not user or not matches(old, user[0]):
            return 401, "login_invalid"
        vaults = dict(db.execute("SELECT slug,wrapped_key FROM account_vaults WHERE account=?", (name,)))
        password_vaults = {slug: key for slug, key in vaults.items() if not key.startswith("v2.")}
        challenge = db.execute("SELECT device,code_hash,expires,sent,attempts FROM password_codes WHERE account=?",
                               (name,)).fetchone()
        if data.get("mode") == "prepare":
            email = db.execute("SELECT email FROM registrations WHERE name=? AND state='approved'", (name,)).fetchone()
            if not email:
                return 403, "email_invalid"
            if challenge and challenge[3] > now - 60:
                return 429, "resend_wait"
            code = f"{secrets.randbelow(1000000):06}"
            digest = password_hash(code)
            db.execute("INSERT OR REPLACE INTO password_codes(account,device,code_hash,expires,sent) VALUES (?,?,?,?,?)",
                       (name, device, digest, now+900, now))
        elif data.get("mode") == "commit":
            new, code, changes = (data.get(field) for field in ("newProof", "code", "vaults"))
            if (not isinstance(new, str) or not PROOF.fullmatch(new) or new == old
                or not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code)
                or not isinstance(changes, dict) or changes.keys() != password_vaults.keys()):
                return 400, "invalid_request"
            for slug, current in password_vaults.items():
                change = changes[slug]
                if not isinstance(change, dict) or change.get("old") != current:
                    return 409, "vault_changed"
                wrapped = change.get("new")
                if not isinstance(wrapped, str) or not WRAPPED_KEY.fullmatch(wrapped) or wrapped.startswith("v2."):
                    return 400, "invalid_request"
            if not challenge or challenge[0] != device or challenge[2] <= now or challenge[4] >= 5:
                return 403, "code_expired"
            if not matches(code, challenge[1]):
                db.execute("UPDATE password_codes SET attempts=attempts+1 WHERE account=?", (name,))
                return 403, "code_invalid"
            for slug, change in changes.items():
                db.execute("UPDATE account_vaults SET wrapped_key=? WHERE account=? AND slug=?", (change["new"], name, slug))
            db.execute("UPDATE account_credentials SET verifier=? WHERE name=?", (password_hash(new), name))
            db.execute("DELETE FROM account_sessions WHERE vault IN (SELECT vault FROM account_vaults WHERE account=?)", (name,))
            db.execute("DELETE FROM password_codes WHERE account=?", (name,))
            return 200, {"ok": True}
        else:
            return 400, "invalid_request"
    try:
        send_code(path, email[0], code, "password")
    except (OSError, KeyError, ValueError, smtplib.SMTPException):
        with database(path) as db:
            db.execute("DELETE FROM password_codes WHERE account=? AND code_hash=?", (name, digest))
        return 503, "mail_unavailable"
    return 200, {"vaults": password_vaults}
