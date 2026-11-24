"""Windows administration panel for the existing SSH-managed sync server."""
import base64
import json
import os
import re
import secrets
import shlex
import subprocess
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

ENDPOINT = "https://blueee.cn:8443/simple-sync"
REMOTE = (
    "runuser", "-u", "simple-note-sync", "--", "python3", "/srv/simple-note-sync/server.py",
    "--db", "/srv/simple-note-sync/data/sync.sqlite3",
)
STATE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SimpleNoteSyncAdmin"
KEYS = STATE / "vault-keys.json"


def remote(*args, stdin=None):
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=7", "blueee-server", shlex.join((*REMOTE, *args))],
        input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        lines = result.stderr.strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "服务器拒绝了操作")
    return result.stdout.strip()


class Manager:
    def __init__(self, window):
        self.window = window
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.keys = json.loads(KEYS.read_text(encoding="utf-8")) if KEYS.exists() else {}
        self.busy = False
        self.users = []
        self.vaults = []
        self.window.title("笔记同步管理")
        self.window.geometry("780x600")
        self.window.minsize(660, 520)
        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="笔记同步管理", font=("Microsoft YaHei UI", 17, "bold")).pack(anchor="w")
        self.status = tk.StringVar(value="正在连接 blueee-server…")
        ttk.Label(frame, textvariable=self.status, wraplength=660).pack(anchor="w", pady=(5, 10))
        self.actions = []
        notebook = ttk.Notebook(frame)
        notebook.pack(fill="both", expand=True)
        account_tab = ttk.Frame(notebook, padding=12)
        legacy_tab = ttk.Frame(notebook, padding=12)
        notebook.add(account_tab, text="账号管理")
        notebook.add(legacy_tab, text="旧版配对")
        self.build_accounts(account_tab)
        self.build_legacy(legacy_tab)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    def build_accounts(self, parent):
        ttk.Label(parent, text="新账号注册、审批与账号状态。", wraplength=680).pack(anchor="w")
        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", pady=(10, 8))
        for label, action in (
            ("设置注册口令", self.set_invite),
            ("关闭注册", self.close_registration),
            ("查看注册账号", self.list_accounts),
            ("停用／启用账号", self.change_account),
            ("配置发信邮箱", self.configure_smtp),
        ):
            self.button(buttons, label, action).pack(side="left", padx=(0, 8))
        ttk.Label(parent, text="待审批注册（只有已验证邮箱的申请会出现）").pack(anchor="w", pady=(10, 4))
        listing = ttk.Frame(parent)
        listing.pack(fill="both", expand=True)
        self.pending = ttk.Treeview(listing, columns=("name", "email"), show="headings",
                                    selectmode="browse", height=8)
        self.pending.heading("name", text="用户名")
        self.pending.heading("email", text="已验证邮箱")
        self.pending.column("name", width=180)
        self.pending.column("email", width=420)
        self.pending.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(listing, orient="vertical", command=self.pending.yview)
        scrollbar.pack(side="right", fill="y")
        self.pending.configure(yscrollcommand=scrollbar.set)
        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(8, 0))
        self.button(controls, "刷新待审批", self.refresh_registrations).pack(side="left", padx=(0, 8))
        self.button(controls, "批准", lambda: self.decide(True)).pack(side="left", padx=(0, 8))
        self.button(controls, "拒绝", lambda: self.decide(False)).pack(side="left")

    def build_legacy(self, parent):
        selectors = ttk.Frame(parent)
        selectors.pack(fill="x", pady=(0, 12))
        selectors.columnconfigure((0, 2), weight=1)
        ttk.Label(selectors, text="用户").grid(row=0, column=0, sticky="w")
        ttk.Label(selectors, text="仓库").grid(row=0, column=2, sticky="w", padx=(12, 4))
        self.user = ttk.Combobox(selectors, state="readonly")
        self.user.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.vault = ttk.Combobox(selectors, state="readonly")
        self.vault.grid(row=1, column=2, sticky="ew", padx=(12, 0), pady=(4, 0))
        self.button(selectors, "新建用户", lambda: self.create("user")).grid(row=1, column=1, padx=(5, 0))
        self.button(selectors, "新建仓库", lambda: self.create("vault")).grid(row=1, column=3, padx=(5, 0))
        self.button(selectors, "导入仓库密钥", self.import_key).grid(row=2, column=2, sticky="w",
                                                                     padx=(12, 0), pady=(6, 0))
        ttk.Label(parent, text="已授权访问").pack(anchor="w")
        listing = ttk.Frame(parent)
        listing.pack(fill="both", expand=True, pady=(5, 12))
        self.rows = ttk.Treeview(listing, columns=("user", "vault"), show="headings", selectmode="browse")
        self.rows.heading("user", text="用户")
        self.rows.heading("vault", text="仓库")
        self.rows.column("user", width=190)
        self.rows.column("vault", width=240)
        self.rows.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(listing, orient="vertical", command=self.rows.yview)
        scrollbar.pack(side="right", fill="y")
        self.rows.configure(yscrollcommand=scrollbar.set)
        bottom = ttk.Frame(parent)
        bottom.pack(fill="x")
        for label, action in (
            ("发放配对配置", lambda: self.issue(False)), ("重置凭据", lambda: self.issue(True)),
            ("撤销授权", self.revoke), ("刷新", self.refresh),
        ):
            self.button(bottom, label, action).pack(side="left", padx=(0, 8))

    def refresh_registrations(self):
        self.submit(("list-registrations",), "正在读取待审批注册…", self.show_pending)

    def show_pending(self, output):
        registrations = json.loads(output)
        children = self.pending.get_children()
        if children:
            self.pending.delete(*children)
        for name, email in registrations:
            self.pending.insert("", "end", values=(name, email))
        self.status.set(f"{len(registrations)} 项待审批" if registrations else "没有待审批注册")

    def decide(self, approve):
        selection = self.pending.selection()
        if not selection:
            messagebox.showinfo("注册审批", "请先选择一条待审批注册。", parent=self.window)
            return
        name, email = self.pending.item(selection[0], "values")
        action = "批准" if approve else "拒绝"
        if not messagebox.askyesno("注册审批", f"{action} {name}（{email}）的注册申请？", parent=self.window):
            return

        def done(_):
            self.status.set(f"已{action} {name} 的注册。")
            self.refresh_registrations()

        command = "approve-registration" if approve else "reject-registration"
        self.submit((command, name), f"正在{action}…", done)

    def button(self, parent, label, action):
        control = ttk.Button(parent, text=label, command=action)
        self.actions.append(control)
        return control

    def close(self):
        self.worker.shutdown(wait=False, cancel_futures=True)
        self.window.destroy()

    def save_keys(self):
        STATE.mkdir(parents=True, exist_ok=True)
        pending = KEYS.with_suffix(".tmp")
        pending.write_text(json.dumps(self.keys, ensure_ascii=False), encoding="utf-8")
        pending.replace(KEYS)

    def submit(self, args, message, on_success, *, stdin=None):
        if self.busy:
            return
        self.busy = True
        for item in self.actions:
            item.state(["disabled"])
        self.status.set(message)
        future = self.worker.submit(remote, *args, stdin=stdin)

        def check():
            if not future.done():
                self.window.after(80, check)
                return
            self.busy = False
            for item in self.actions:
                item.state(["!disabled"])
            try:
                on_success(future.result())
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                self.status.set("操作未完成")
                messagebox.showerror("笔记同步管理", str(error), parent=self.window)

        self.window.after(80, check)

    def configure_smtp(self):
        parent = self.window
        address = simpledialog.askstring("发信邮箱", "输入专门用于发验证码的 SMTP 邮箱", parent=parent)
        if not address:
            return
        address = address.strip().lower()
        host = simpledialog.askstring("发信邮箱", "输入 SMTP 主机名",
                                      initialvalue="smtp.qq.com" if address.endswith("@qq.com") else "",
                                      parent=parent)
        if not host:
            return
        port = simpledialog.askinteger("发信邮箱", "SMTP 端口（465 或 587）", initialvalue=465, parent=parent)
        if port not in (465, 587):
            return
        username = simpledialog.askstring("发信邮箱", "SMTP 用户名", initialvalue=address, parent=parent)
        if not username:
            return
        password = simpledialog.askstring("发信邮箱", "SMTP 授权码或应用密码", show="*", parent=parent)
        if not password:
            return
        config = dict(address=address, host=host.strip(), port=port, username=username.strip(), password=password)
        self.submit(("set-smtp",), "正在保存发信配置…",
                    lambda _: self.status.set("发信配置已保存，可以申请注册并验证邮箱。"),
                    stdin=json.dumps(config) + "\n")

    def set_invite(self):
        code = simpledialog.askstring("设置注册口令", "请输入至少 12 个字符的注册口令",
                                      show="*", parent=self.window)
        if code is None:
            return
        if not 12 <= len(code) <= 256:
            messagebox.showerror("口令长度", "请输入 12–256 个字符。", parent=self.window)
            return
        again = simpledialog.askstring("确认注册口令", "请再输入一次", show="*", parent=self.window)
        if again != code:
            return
        self.submit(("set-registration-invite", "--stdin"), "正在设置口令…",
                    lambda _: self.status.set("注册已开放，使用新口令注册。"), stdin=code + "\n")

    def close_registration(self):
        if messagebox.askyesno("关闭注册", "关闭新账号注册？已有用户仍可登录。", parent=self.window):
            self.submit(("close-registration",), "正在关闭注册…",
                        lambda _: self.status.set("注册已关闭。"))

    def list_accounts(self):
        self.submit(("account-details",), "正在读取账号…", self.show_accounts)

    def show_accounts(self, output):
        entries = json.loads(output)
        self.status.set(f"{len(entries)} 个注册账号")
        panel = tk.Toplevel(self.window)
        panel.title("注册账号")
        panel.geometry("620x330")
        listing = ttk.Treeview(panel, columns=("name", "email", "state"), show="headings")
        listing.heading("name", text="用户名")
        listing.heading("email", text="已验证邮箱")
        listing.heading("state", text="状态")
        listing.column("name", width=160)
        listing.column("email", width=300)
        listing.column("state", width=100)
        listing.pack(fill="both", expand=True, padx=12, pady=12)
        for entry in entries:
            listing.insert("", "end", values=(entry["name"], entry["email"] or "未记录",
                                              "停用" if entry["disabled"] else "正常"))

    def change_account(self):
        name = simpledialog.askstring("停用／启用账号", "请输入注册账号名", parent=self.window)
        if not name:
            return
        disabled = messagebox.askyesnocancel("修改账号", "选「是」停用账号，选「否」重新启用。",
                                             parent=self.window)
        if disabled is None:
            return
        command = "disable-account" if disabled else "enable-account"
        self.submit((command, name.strip()), "正在更新账号…",
                    lambda _: self.status.set("账号已停用。" if disabled else "账号已启用。"))

    def refresh(self):
        def display(output):
            state = json.loads(output)
            self.users, self.vaults = state["users"], state["vaults"]
            for select, values in ((self.user, self.users), (self.vault, self.vaults)):
                selected = select.get()
                select.configure(values=values)
                select.set(selected if selected in values else next(iter(values), ""))
            children = self.rows.get_children()
            if children:
                self.rows.delete(*children)
            for user, vault in state["access"]:
                self.rows.insert("", "end", values=(user, vault))
            self.status.set(f"{len(self.users)} 位用户 · {len(self.vaults)} 个仓库 · {len(state['access'])} 项授权")
            self.refresh_registrations()

        self.submit(("admin-list",), "正在读取用户和仓库…", display)

    def create(self, kind):
        noun = "用户" if kind == "user" else "仓库"
        name = simpledialog.askstring("新建" + noun, noun + "名称", parent=self.window)
        if name is None or not name.strip():
            return
        name = name.strip()
        if name in (self.users if kind == "user" else self.vaults):
            messagebox.showinfo("名称已存在", name, parent=self.window)
            return
        if kind == "vault" and name not in self.keys:
            try:
                self.keys[name] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                self.save_keys()
            except OSError as error:
                self.keys.pop(name, None)
                messagebox.showerror("无法保存仓库密钥", str(error), parent=self.window)
                return
        self.submit(("create-" + kind, name), "正在新建" + noun + "…", lambda _: self.refresh())

    def import_key(self):
        vault = self.vault.get()
        if not vault:
            messagebox.showinfo("请选择仓库", "先在上方选择要导入密钥的仓库。", parent=self.window)
            return
        filename = filedialog.askopenfilename(parent=self.window, filetypes=[("配对配置", "*.json")])
        if not filename:
            return
        previous = self.keys.get(vault)
        try:
            key = json.loads(Path(filename).read_text(encoding="utf-8-sig"))["key"]
            if len(base64.b64decode(key, validate=True)) != 32:
                raise ValueError("密钥必须是 32 字节")
            if previous is not None and previous != key:
                raise ValueError("已保存这个仓库的密钥，请先核对选择的文件。")
            self.keys[vault] = key
            self.save_keys()
        except (OSError, ValueError, TypeError, KeyError) as error:
            if previous is None:
                self.keys.pop(vault, None)
            else:
                self.keys[vault] = previous
            messagebox.showerror("无法导入密钥", str(error), parent=self.window)
        else:
            self.status.set(f"已导入「{vault}」的仓库密钥")

    def selected(self):
        selection = self.rows.selection()
        if selection:
            return tuple(self.rows.item(selection[0], "values"))
        messagebox.showinfo("请选择授权", "请在「已授权访问」里选择一项。", parent=self.window)
        return None

    def issue(self, rotate):
        selected = self.selected() if rotate else (self.user.get(), self.vault.get())
        if not selected:
            return
        user, vault = selected
        if not user or not vault:
            messagebox.showinfo("请选择用户和仓库", "请在上方选择授权对象。", parent=self.window)
            return
        if vault not in self.keys:
            messagebox.showinfo("需要仓库密钥", "请先为这个仓库导入已有配对配置中的密钥。", parent=self.window)
            return
        if rotate and not messagebox.askyesno("重置凭据", f"重置后，{user} 的原配对配置将失效。继续？",
                                              parent=self.window):
            return

        def delivered(token):
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                raise ValueError("服务器没有返回有效凭据")
            config = json.dumps({"url": ENDPOINT, "token": token, "key": self.keys[vault]}, separators=(",", ":"))
            self.window.clipboard_clear()
            self.window.clipboard_append(config)
            self.status.set(f"已复制 {user} 的配对配置")
            messagebox.showinfo("配对配置已复制", "请私下交给这位用户。配置含有访问凭据。", parent=self.window)
            self.refresh()

        self.submit(("rotate" if rotate else "invite", user, vault), "正在发放凭据…", delivered)

    def revoke(self):
        selected = self.selected()
        if selected and messagebox.askyesno("撤销授权", f"停止 {selected[0]} 同步「{selected[1]}」？",
                                            parent=self.window):
            self.submit(("revoke", *selected), "正在撤销授权…", lambda _: self.refresh())


if __name__ == "__main__":
    root = tk.Tk()
    Manager(root)
    root.mainloop()
