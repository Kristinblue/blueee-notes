const {requestUrl, Setting} = require("obsidian");
const {encode64, decode64} = require("./engine");

const SERVICE = "https://blueee.cn:8443/simple-sync";
const NAME = /^[a-z0-9][a-z0-9_-]{2,39}$/;
const encoder = new TextEncoder();

const ERRORS = {
    invalid_request: "账号或远端仓库名需要 3–40 个小写字母、数字、横线或下划线。",
    registration_closed: "服务器还没有开放注册，请联系管理员。",
    invite_invalid: "注册口令错误或已更换。",
    email_invalid: "请输入有效的邮箱地址。",
    registration_conflict: "该账号名或邮箱已用于其他注册，请联系管理员。",
    mail_unavailable: "验证码发送失败，请联系管理员检查发件邮箱。",
    resend_wait: "请等一分钟后再申请发送验证码。",
    code_invalid: "验证码或账号信息不正确。",
    code_expired: "验证码已过期或错误次数过多，请重新发送。",
    approval_pending: "邮箱已验证，等待管理员审批后才能登录。",
    account_exists: "这个账号已存在，请登录或换个账号名。",
    login_invalid: "账号或密码错误，或账号已被停用。",
    vault_missing: "这个账号下没有该仓库，请核对名称或选择新建远端仓库。",
    vault_exists: "这个远端仓库已存在，请选择登录。",
    busy: "登录服务正忙，请稍后重试。",
};

async function accountKeys(username, password) {
    const secret = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({
        name: "PBKDF2", hash: "SHA-256", iterations: 600000,
        salt: encoder.encode("blueee-notes-account-v1:" + username),
    }, secret, 512);
    const wrap = await crypto.subtle.importKey("raw", bits.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]);
    return {proof: encode64(new Uint8Array(bits.slice(0, 32))), wrap};
}

function wrappingContext(account, vault, salt) {
    return encoder.encode("blueee-notes-vault-key-v1:" + account + ":" + vault + ":" + salt);
}

async function connectAccount({mode, account, vault, password, invite, email, code}) {
    account = account.toLowerCase();
    if (!NAME.test(account) || !NAME.test(vault)) throw Error(ERRORS.invalid_request);
    if (password.length < 6 || password.length > 256) throw Error("请输入 6–256 个字符的密码。");
    if (mode === "register" && !invite) throw Error("请输入管理员给你的注册口令。");
    const {proof, wrap} = await accountKeys(account, password);
    const data = {mode, account, vault, proof};
    if (mode === "register" || mode === "verify") {
        data.email = (email ?? "").trim().toLowerCase();
        if (!data.email || !data.email.includes("@")) throw Error(ERRORS.email_invalid);
    }
    if (mode === "register") data.invite = invite;
    if (mode === "verify") data.code = code;
    if (mode === "register" || mode === "create") {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const salt = encode64(crypto.getRandomValues(new Uint8Array(16)));
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({
            name: "AES-GCM", iv: nonce, additionalData: wrappingContext(account, vault, salt),
        }, wrap, key);
        data.wrappedKey = [salt, encode64(nonce), encode64(new Uint8Array(encrypted))].join(".");
    }
    let response;
    try {
        response = await requestUrl({url: SERVICE + "/v1/account/connect", method: "POST",
            contentType: "application/json", body: JSON.stringify(data), throw: false});
    } catch {
        throw Error("无法连接 Blueee Notes 登录服务，请检查网络后重试。");
    }
    if (response.status === 202) return {status: response.json.status};
    if (response.status !== 200) {
        let message;
        try { message = ERRORS[response.json.error]; } catch { /* A proxy may return a non-JSON response. */ }
        throw Error(message ?? "登录服务暂时不可用。");
    }
    const {token, wrappedKey} = response.json;
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw Error("登录服务返回无效会话。");
    const [salt, nonce, ciphertext] = wrappedKey.split(".");
    const key = await crypto.subtle.decrypt({
        name: "AES-GCM", iv: decode64(nonce), additionalData: wrappingContext(account, vault, salt),
    }, wrap, decode64(ciphertext));
    if (key.byteLength !== 32) throw Error("仓库密钥无效。");
    return {url: SERVICE, token, key: encode64(new Uint8Array(key)), account, vault};
}

function accountForm(parent, plugin, done) {
    const pair = plugin.state.pair;
    const lockedVault = Boolean(pair?.account);
    const root = parent.createEl("form", {cls: "simple-note-sync-account"});
    const form = {mode: "login"};
    let action;
    const setMode = mode => {
        form.mode = mode;
        const registering = mode === "register";
        const verifying = mode === "verify";
        emailRow.settingEl.hidden = !(registering || verifying);
        inviteRow.settingEl.hidden = !registering;
        codeRow.settingEl.hidden = !verifying;
        email.required = registering || verifying;
        invite.required = registering;
        code.required = verifying;
        submit.setText(registering ? "发送验证码" : verifying ? "验证邮箱" : "连接 Blueee Notes");
    };
    new Setting(root).setName("账号操作").addDropdown(field => {
        action = field;
        field.addOption("login", "登录并连接已有仓库");
        if (!lockedVault) {
            field.addOption("register", "用口令注册");
            field.addOption("verify", "填写邮件验证码");
            field.addOption("create", "已有账号，新建远端仓库");
        }
        field.onChange(setMode);
    });
    const inputs = {};
    for (const [id, label, type, initial, autocomplete] of [
        ["account", "账号", "text", pair?.account ?? "", "username"],
        ["password", "密码", "password", "", "current-password"],
        ["vault", "远端仓库名", "text", pair?.vault ?? "main", "off"],
    ]) {
        new Setting(root).setName(label).addText(field => {
            field.setValue(initial);
            const input = field.inputEl;
            input.type = type;
            input.autocomplete = autocomplete;
            input.setAttribute("aria-label", label);
            input.required = true;
            input.readOnly = lockedVault && id !== "password";
            inputs[id] = input;
        });
    }
    let email;
    const emailRow = new Setting(root).setName("邮箱").addText(field => {
        email = field.inputEl;
        email.type = "email";
        email.autocomplete = "email";
        email.setAttribute("aria-label", "邮箱");
    });
    let code;
    const codeRow = new Setting(root).setName("邮件验证码").addText(field => {
        code = field.inputEl;
        code.inputMode = "numeric";
        code.maxLength = 6;
        code.autocomplete = "one-time-code";
        code.setAttribute("aria-label", "邮件验证码");
    });
    let invite;
    const inviteRow = new Setting(root).setName("管理员注册口令").addText(field => {
        invite = field.inputEl;
        invite.type = "password";
        invite.autocomplete = "off";
        invite.setAttribute("aria-label", "管理员注册口令");
    });
    const feedback = root.createDiv({cls: "simple-note-sync-status", attr: {role: "status"}});
    const submit = root.createEl("button", {text: "连接 Blueee Notes", cls: "mod-cta", attr: {type: "submit"}});
    setMode("login");
    root.addEventListener("submit", async event => {
        event.preventDefault();
        submit.disabled = true;
        feedback.dataset.state = "info";
        feedback.setText("正在连接…");
        try {
            const result = await plugin.connectAccount({
                mode: form.mode,
                account: inputs.account.value.trim().toLowerCase(),
                vault: inputs.vault.value.trim(),
                password: inputs.password.value,
                invite: invite.value,
                email: email.value,
                code: code.value.trim(),
            });
            invite.value = "";
            if (result === "verification_required") {
                action.setValue("verify");
                setMode("verify");
                feedback.setText("已发送验证码，有效期 15 分钟。");
                code.focus();
            } else if (result === "approval_pending") {
                inputs.password.value = code.value = "";
                action.setValue("login");
                setMode("login");
                feedback.setText(ERRORS.approval_pending);
            } else {
                inputs.password.value = code.value = "";
                done();
            }
        } catch (error) {
            feedback.dataset.state = "error";
            feedback.setText(error.message);
        } finally {
            submit.disabled = false;
        }
    });
}

module.exports = {accountForm, connectAccount};
