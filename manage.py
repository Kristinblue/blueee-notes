"""Windows administration panel for the SSH-managed sync server."""
import json
import shlex
import subprocess
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk

REMOTE = (
    "runuser", "-u", "simple-note-sync", "--", "python3", "/srv/simple-note-sync/server.py",
    "--db", "/srv/simple-note-sync/data/sync.sqlite3",
)


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
        self.busy = False
        self.window.title("笔记同步管理")
        self.window.geometry("780x600")
        self.window.minsize(660, 520)
        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="笔记同步管理", font=("Microsoft YaHei UI", 17, "bold")).pack(anchor="w")
        self.status = tk.StringVar(value="正在连接 blueee-server…")
        ttk.Label(frame, textvariable=self.status, wraplength=660).pack(anchor="w", pady=(5, 10))
        self.actions = []
        ttk.Label(frame, text="新账号注册、审批与账号状态。", wraplength=680).pack(anchor="w")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(10, 8))
        for label, action in (
            ("设置注册口令", self.set_invite),
            ("关闭注册", self.close_registration),
            ("查看注册账号", self.list_accounts),
            ("停用／启用账号", self.change_account),
            ("配置发信邮箱", self.configure_smtp),
        ):
            self.button(buttons, label, action).pack(side="left", padx=(0, 8))
        ttk.Label(frame, text="待审批注册（只有已验证邮箱的申请会出现）").pack(anchor="w", pady=(10, 4))
        listing = ttk.Frame(frame)
        listing.pack(fill="both", expand=True)
        self.pending = ttk.Treeview(listing, columns=("name", "email"), show="headings",
                                    selectmode="browse", height=10)
        self.pending.heading("name", text="用户名")
        self.pending.heading("email", text="已验证邮箱")
        self.pending.column("name", width=180)
        self.pending.column("email", width=440)
        self.pending.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(listing, orient="vertical", command=self.pending.yview)
        scrollbar.pack(side="right", fill="y")
        self.pending.configure(yscrollcommand=scrollbar.set)
        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=(8, 0))
        self.button(controls, "刷新待审批", self.refresh_registrations).pack(side="left", padx=(0, 8))
        self.button(controls, "批准", lambda: self.decide(True)).pack(side="left", padx=(0, 8))
        self.button(controls, "拒绝", lambda: self.decide(False)).pack(side="left")
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh_registrations()

    def button(self, parent, label, action):
        control = ttk.Button(parent, text=label, command=action)
        self.actions.append(control)
        return control

    def close(self):
        self.worker.shutdown(wait=False, cancel_futures=True)
        self.window.destroy()

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


if __name__ == "__main__":
    root = tk.Tk()
    Manager(root)
    root.mainloop()
