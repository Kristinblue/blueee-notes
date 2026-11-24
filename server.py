"""Authenticated storage for encrypted Obsidian files."""
import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import accounts

ID = re.compile(r"[0-9a-f]{64}")
MAX_REQUEST = 64 * 1024 * 1024
DEVICE = re.compile(r"[0-9a-f-]{36}")


@contextmanager
def database(path):
    db = sqlite3.connect(path, timeout=20)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        with db:
            yield db
    finally:
        db.close()


def init(path):
    with database(path) as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS vaults (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS access (
          user TEXT REFERENCES users(name), vault TEXT REFERENCES vaults(name),
          token_hash TEXT UNIQUE NOT NULL, PRIMARY KEY(user, vault)
        );
        CREATE TABLE IF NOT EXISTS files (
          vault TEXT REFERENCES vaults(name), id TEXT, revision INTEGER NOT NULL,
          metadata TEXT NOT NULL, data TEXT, PRIMARY KEY(vault, id)
        );
        CREATE TABLE IF NOT EXISTS history (
          vault TEXT, id TEXT, revision INTEGER, data TEXT, superseded INTEGER NOT NULL,
          PRIMARY KEY(vault,id,revision)
        );
        CREATE TABLE IF NOT EXISTS acknowledgements (
          vault TEXT, id TEXT, device TEXT, revision INTEGER NOT NULL, seen INTEGER NOT NULL,
          PRIMARY KEY(vault,id,device)
        );
        """)
        db.executescript(accounts.SCHEMA)


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def grant(path, user, vault):
    token = secrets.token_urlsafe(32)
    with database(path) as db:
        db.execute("INSERT OR IGNORE INTO users VALUES (?)", (user,))
        db.execute("INSERT OR IGNORE INTO vaults VALUES (?)", (vault,))
        db.execute("""INSERT INTO access VALUES (?,?,?) ON CONFLICT(user,vault)
                      DO UPDATE SET token_hash=excluded.token_hash""",
                   (user, vault, token_hash(token)))
    return token


def admin_snapshot(path):
    with database(path) as db:
        return {
            "users": [name for (name,) in db.execute("SELECT name FROM users ORDER BY name")],
            "vaults": [name for (name,) in db.execute("""SELECT name FROM vaults
                       WHERE name NOT IN (SELECT vault FROM account_vaults) ORDER BY name""")],
            "access": list(db.execute("SELECT user,vault FROM access ORDER BY vault,user")),
        }


def validate_name(value):
    if not value or len(value) > 80 or value.startswith("-") or any(ord(c) < 32 for c in value):
        raise argparse.ArgumentTypeError("Invalid account or vault name")
    return value


def admin_issue(path, user, vault, rotate):
    token = secrets.token_urlsafe(32)
    with database(path) as db:
        if rotate:
            result = db.execute("UPDATE access SET token_hash=? WHERE user=? AND vault=?",
                                (token_hash(token), user, vault))
            if result.rowcount != 1:
                raise ValueError("未找到这项授权")
        else:
            db.execute("INSERT INTO access VALUES (?,?,?)", (user, vault, token_hash(token)))
    return token


def handler(path):
    class SyncHandler(BaseHTTPRequestHandler):
        def reply(self, status, value):
            payload = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def authorize(self, db):
            value = self.headers.get("Authorization", "")
            if not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", value):
                return None
            row = db.execute("SELECT vault FROM access WHERE token_hash=?",
                             (token_hash(value[7:]),)).fetchone()
            if row:
                return row[0]
            row = db.execute("""
                SELECT s.vault FROM account_sessions s
                JOIN account_vaults v ON v.vault=s.vault
                JOIN account_credentials a ON a.name=v.account
                WHERE s.token_hash=? AND s.expires>? AND a.disabled=0
            """, (token_hash(value[7:]), int(time.time()))).fetchone()
            if row:
                session = self.device_session(db)
                if session:
                    now = int(time.time())
                    db.execute("UPDATE account_devices SET last_seen=? WHERE account=? AND id=? AND last_seen<?",
                               (now, *session, now-60))
            return row[0] if row else None

        def device_session(self, db):
            token = self.headers.get("Authorization", "")
            if not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", token):
                return None
            return db.execute("""SELECT d.account,d.device FROM device_sessions d
                JOIN account_sessions s ON s.token_hash=d.token_hash
                JOIN account_credentials a ON a.name=d.account
                WHERE d.token_hash=? AND s.expires>? AND a.disabled=0
            """, (token_hash(token[7:]), int(time.time()))).fetchone()

        def do_GET(self):
            url = urlsplit(self.path)
            route = url.path
            with database(path) as db:
                vault = self.authorize(db)
                if vault is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
                if route == "/v1/account/profile":
                    current = self.device_session(db)
                    if not current:
                        self.reply(401, {"error": "unauthorized"})
                        return
                    name = current[0]
                    email = db.execute("SELECT email FROM registrations WHERE name=? AND state='approved'",
                                       (name,)).fetchone()
                    rows = db.execute("SELECT slug FROM account_vaults WHERE account=? ORDER BY slug", (name,))
                    self.reply(200, {"name": name, "email": email[0] if email else None,
                                     "vaults": [slug for (slug,) in rows]})
                    return
                if route == "/v1/account/devices":
                    current = self.device_session(db)
                    if not current:
                        self.reply(401, {"error": "unauthorized"})
                        return
                    name, device = current
                    now = int(time.time())
                    rows = db.execute("""SELECT d.id,d.label,d.first_seen,d.last_seen,
                      EXISTS(SELECT 1 FROM device_sessions ds JOIN account_sessions ss
                        ON ss.token_hash=ds.token_hash WHERE ds.account=d.account
                        AND ds.device=d.id AND ss.expires>?)
                      FROM account_devices d WHERE d.account=? ORDER BY d.last_seen DESC""", (now,name))
                    self.reply(200, [{"id": key, "name": label, "firstSeen": first, "lastSeen": last,
                                      "current": key == device, "active": bool(active)}
                                     for key,label,first,last,active in rows])
                    return
                if route == "/v1/plugin-list":
                    row = db.execute("SELECT encrypted_list FROM plugin_lists WHERE vault=?", (vault,)).fetchone()
                    self.reply(200, {"encrypted": row[0] if row else None})
                    return
                if route == "/v1/manifest":
                    target = parse_qs(url.query).get("id", [None])[0]
                    if target is not None and not ID.fullmatch(target):
                        self.reply(400, {"error": "invalid file id"})
                        return
                    if target is None:
                        rows = db.execute("SELECT id,revision,metadata FROM files WHERE vault=?", (vault,))
                    else:
                        rows = db.execute("SELECT id,revision,metadata FROM files WHERE vault=? AND id=?",
                                          (vault, target))
                    self.reply(200, [{"id": key, "revision": rev, "metadata": meta}
                                     for key, rev, meta in rows])
                    return
                key = route.removeprefix("/v1/files/")
                if route.startswith("/v1/files/") and ID.fullmatch(key):
                    row = db.execute("SELECT revision,data FROM files WHERE vault=? AND id=?",
                                     (vault, key)).fetchone()
                    requested = parse_qs(url.query).get("revision", [None])[0]
                    if requested is not None:
                        if not re.fullmatch(r"[1-9][0-9]{0,14}", requested):
                            self.reply(400, {"error": "invalid revision"})
                            return
                        if not row or row[0] != int(requested):
                            row = db.execute("""SELECT revision,data FROM history
                                                WHERE vault=? AND id=? AND revision=?""",
                                             (vault, key, int(requested))).fetchone()
                    if row:
                        self.reply(200, {"revision": row[0], "data": row[1]})
                        return
                self.reply(404, {"error": "not found"})

        def do_POST(self):
            route = urlsplit(self.path).path
            if route == "/v1/account/connect":
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 4096:
                        raise ValueError
                    body = json.loads(self.rfile.read(size))
                except (ValueError, RecursionError):
                    self.reply(400, {"error": "invalid_request"})
                    return
                status, result = accounts.connect(database, path, body, token_hash)
                self.reply(status, result if status in (200, 202) else {"error": result})
                return
            if route == "/v1/account/upgrade-wrap":
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 512:
                        raise ValueError
                    data = json.loads(self.rfile.read(size))
                    previous, wrapped = data["previous"], data["wrapped"]
                    if (not accounts.WRAPPED_KEY.fullmatch(previous) or not previous.startswith("v2.")
                        or not accounts.WRAPPED_KEY.fullmatch(wrapped) or wrapped.startswith("v2.")):
                        raise ValueError
                except (ValueError, KeyError, TypeError, RecursionError):
                    self.reply(400, {"error": "invalid_request"})
                    return
                with database(path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    current = self.device_session(db)
                    vault = self.authorize(db)
                    if not current or not vault:
                        self.reply(401, {"error": "unauthorized"})
                        return
                    result = db.execute("""UPDATE account_vaults SET wrapped_key=?
                        WHERE account=? AND vault=? AND wrapped_key=?""", (wrapped,current[0],vault,previous))
                    if not result.rowcount:
                        self.reply(409, {"error": "revision changed"})
                        return
                self.reply(200, {"ok": True})
                return
            if route == "/v1/account/password":
                with database(path) as db:
                    current = self.device_session(db)
                if not current:
                    self.reply(401, {"error": "unauthorized"})
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 256 * 1024:
                        raise ValueError
                    body = json.loads(self.rfile.read(size))
                except (ValueError, RecursionError):
                    self.reply(400, {"error": "invalid_request"})
                    return
                status, result = accounts.change_password(database, path, current, body)
                self.reply(status, result if status == 200 else {"error": result})
                return
            if route == "/v1/account/devices/revoke":
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 120:
                        raise ValueError
                    device = json.loads(self.rfile.read(size))["id"]
                    if not ID.fullmatch(device):
                        raise ValueError
                except (KeyError, TypeError, ValueError, RecursionError):
                    self.reply(400, {"error": "invalid_request"})
                    return
                with database(path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    current = self.device_session(db)
                    if not current:
                        self.reply(401, {"error": "unauthorized"})
                        return
                    name = current[0]
                    db.execute("""DELETE FROM account_sessions WHERE token_hash IN
                        (SELECT token_hash FROM device_sessions WHERE account=? AND device=?)""", (name,device))
                    db.execute("DELETE FROM device_codes WHERE account=? AND device=?", (name,device))
                    db.execute("DELETE FROM account_devices WHERE account=? AND id=?", (name,device))
                self.reply(200, {"ok": True})
                return
            if route == "/v1/plugin-list":
                self.save_plugin_list()
                return
            if route != "/v1/ack":
                self.reply(404, {"error": "not found"})
                return
            with database(path) as db:
                if self.authorize(db) is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 256:
                    raise ValueError
                body = json.loads(self.rfile.read(size))
                key, device, revision = body["id"], body["device"], body["revision"]
                if not ID.fullmatch(key) or not DEVICE.fullmatch(device) or type(revision) is not int or revision < 1:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                self.reply(400, {"error": "invalid acknowledgement"})
                return
            with database(path) as db:
                db.execute("BEGIN IMMEDIATE")
                vault = self.authorize(db)
                if vault is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
                row = db.execute("SELECT revision FROM files WHERE vault=? AND id=?", (vault, key)).fetchone()
                if not row or revision > row[0]:
                    self.reply(409, {"error": "unknown revision"})
                    return
                now = int(time.time())
                db.execute("""INSERT INTO acknowledgements VALUES (?,?,?,?,?)
                    ON CONFLICT(vault,id,device) DO UPDATE SET
                    revision=max(acknowledgements.revision,excluded.revision), seen=excluded.seen""",
                           (vault, key, device, revision, now))
                db.execute("""DELETE FROM history WHERE vault=? AND id=? AND superseded < ?
                    AND revision < (SELECT min(revision) FROM acknowledgements
                                    WHERE vault=? AND id=? AND seen >= ?)""",
                           (vault, key, now - 7 * 86400, vault, key, now - 30 * 86400))
            self.reply(200, {"ok": True})

        def save_plugin_list(self):
            with database(path) as db:
                if self.authorize(db) is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 128 * 1024:
                    raise ValueError
                value = json.loads(self.rfile.read(size))["encrypted"]
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+", value):
                    raise ValueError
            except (ValueError, TypeError, KeyError, RecursionError):
                self.reply(400, {"error": "invalid plugin list"})
                return
            with database(path) as db:
                db.execute("BEGIN IMMEDIATE")
                vault = self.authorize(db)
                if vault is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
                db.execute("""INSERT INTO plugin_lists VALUES (?,?) ON CONFLICT(vault)
                              DO UPDATE SET encrypted_list=excluded.encrypted_list""", (vault, value))
            self.reply(200, {"ok": True})

        def do_PUT(self):
            route = urlsplit(self.path).path
            key = route.removeprefix("/v1/files/")
            if not route.startswith("/v1/files/") or not ID.fullmatch(key):
                self.reply(404, {"error": "not found"})
                return
            with database(path) as db:
                if self.authorize(db) is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_REQUEST:
                    self.reply(413, {"error": "invalid request size"})
                    return
                body = json.loads(self.rfile.read(size))
                previous, metadata, data = body["previous"], body["metadata"], body["data"]
                if type(previous) is not int or previous < 0:
                    raise ValueError
                if not isinstance(metadata, str) or not 1 <= len(metadata) <= 8192:
                    raise ValueError
                if data is not None and not isinstance(data, str):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                self.reply(400, {"error": "invalid request"})
                return
            with database(path) as db:
                db.execute("BEGIN IMMEDIATE")
                vault = self.authorize(db)
                if vault is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
                row = db.execute("SELECT revision,data FROM files WHERE vault=? AND id=?",
                                 (vault, key)).fetchone()
                current = row[0] if row else 0
                if current != previous:
                    self.reply(409, {"error": "revision changed"})
                    return
                revision = current + 1
                if row:
                    db.execute("INSERT INTO history VALUES (?,?,?,?,?)", (vault, key, current, row[1], int(time.time())))
                db.execute("""INSERT INTO files VALUES (?,?,?,?,?) ON CONFLICT(vault,id)
                              DO UPDATE SET revision=excluded.revision,
                              metadata=excluded.metadata,data=excluded.data""",
                           (vault, key, revision, metadata, data))
            self.reply(200, {"revision": revision})

    return SyncHandler


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="sync.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    commands.add_parser("admin-list")
    invite = commands.add_parser("set-registration-invite")
    invite.add_argument("--stdin", action="store_true")
    commands.add_parser("close-registration")
    commands.add_parser("list-accounts")
    commands.add_parser("account-details")
    commands.add_parser("list-registrations")
    commands.add_parser("set-smtp")
    commands.add_parser("mail-status")
    for action in ("approve-registration", "reject-registration"):
        command = commands.add_parser(action)
        command.add_argument("name", type=validate_name)
    for action in ("disable-account", "enable-account"):
        command = commands.add_parser(action)
        command.add_argument("name", type=validate_name)
    accept = commands.add_parser("serve")
    accept.add_argument("--port", type=int, default=8765)
    for action in ("grant", "revoke", "invite", "rotate"):
        command = commands.add_parser(action)
        command.add_argument("user", type=validate_name)
        command.add_argument("vault", type=validate_name)
    for action in ("create-user", "create-vault"):
        command = commands.add_parser(action)
        command.add_argument("name", type=validate_name)
    args = parser.parse_args()
    path = Path(args.db)
    init(path)
    if args.command == "serve":
        with ThreadingHTTPServer(("127.0.0.1", args.port), handler(path)) as server:
            server.serve_forever()
    elif args.command == "grant":
        print(grant(path, args.user, args.vault))
    elif args.command == "revoke":
        with database(path) as db:
            db.execute("DELETE FROM access WHERE user=? AND vault=?", (args.user, args.vault))
    elif args.command == "mail-status":
        print("configured" if accounts.mail_path(path).is_file() else "unconfigured")
    elif args.command == "set-smtp":
        config = json.loads(sys.stdin.readline(8192))
        if not isinstance(config, dict) or config.get("port") not in (465, 587):
            raise SystemExit("SMTP 端口请使用 465 或 587。")
        for field in ("host", "address", "username", "password"):
            value = config.get(field)
            if not isinstance(value, str) or not value or len(value) > 1024 or "\n" in value or "\r" in value:
                raise SystemExit("SMTP 配置字段无效。")
        if not accounts.EMAIL.fullmatch(config["address"]):
            raise SystemExit("发件邮箱无效。")
        destination = accounts.mail_path(path)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(config), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(destination)
    elif args.command == "account-details":
        with database(path) as db:
            rows = db.execute("""SELECT a.name, r.email, a.disabled
                FROM account_credentials a LEFT JOIN registrations r
                  ON r.name=a.name AND r.state='approved' ORDER BY a.name""")
            print(json.dumps([{"name": name, "email": email, "disabled": bool(disabled)}
                              for name,email,disabled in rows]))
    elif args.command == "list-registrations":
        with database(path) as db:
            print(json.dumps(list(db.execute("""
                SELECT name,email FROM registrations WHERE state='pending' ORDER BY sent,name
            """))))
    elif args.command in ("approve-registration", "reject-registration"):
        with database(path) as db:
            accounts.decide(db, args.name.lower(), args.command == "approve-registration")
    elif args.command in ("set-registration-invite", "close-registration", "list-accounts",
                          "disable-account", "enable-account"):
        with database(path) as db:
            if args.command == "set-registration-invite":
                accounts.set_invite(db, sys.stdin.readline(258).rstrip("\r\n") if args.stdin else None)
            elif args.command == "close-registration":
                db.execute("INSERT OR IGNORE INTO server_settings VALUES ('registration_closed','1')")
            elif args.command == "list-accounts":
                for name, disabled in db.execute("SELECT name,disabled FROM account_credentials ORDER BY name"):
                    print(f"{name}\t{'disabled' if disabled else 'active'}")
            else:
                disabled = args.command == "disable-account"
                db.execute("BEGIN IMMEDIATE")
                if not db.execute("UPDATE account_credentials SET disabled=? WHERE name=?",
                                  (int(disabled), args.name)).rowcount:
                    raise SystemExit("账号不存在")
                if disabled:
                    db.execute("""DELETE FROM account_sessions WHERE vault IN
                                  (SELECT vault FROM account_vaults WHERE account=?)""", (args.name,))
    elif args.command == "list":
        with database(path) as db:
            for vault, user in db.execute("""SELECT vaults.name,access.user FROM vaults
                                             LEFT JOIN access ON vaults.name=access.vault
                                             ORDER BY vaults.name,access.user"""):
                print(f"{vault}\t{user or '-'}")
    elif args.command == "admin-list":
        print(json.dumps(admin_snapshot(path)))
    elif args.command in ("create-user", "create-vault"):
        try:
            with database(path) as db:
                if args.command == "create-user":
                    db.execute("INSERT INTO users VALUES (?)", (args.name,))
                else:
                    db.execute("INSERT INTO vaults VALUES (?)", (args.name,))
        except sqlite3.IntegrityError as error:
            raise SystemExit("名称已存在") from error
    elif args.command in ("invite", "rotate"):
        try:
            print(admin_issue(path, args.user, args.vault, args.command == "rotate"))
        except sqlite3.IntegrityError as error:
            raise SystemExit("请检查仓库和用户是否存在，以及授权是否已发放") from error
        except ValueError as error:
            raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
