const {requestUrl, Setting} = require("obsidian");
const {encode64, decode64} = require("./engine");

const SERVICE = "https://blueee.cn:8443/simple-sync";
const NAME = /^[a-z0-9][a-z0-9_-]{2,39}$/;
const encoder = new TextEncoder();

const ERRORS = {
    invalid_request: "账号或远端仓库名需要 3–40 个小写字母、数字、横线或下划线。",
    registration_closed: "服务器还没有开放注册，请联系管理员。",
    invite_invalid: "注册口令错误或已更换。",
    invite_step_required: "口令验证已过期，请重新输入口令。",
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

function wrappingContext(account, vault, salt, version) {
    return encoder.encode("blueee-notes-vault-key-" + version + ":" + account + ":" + vault + ":" + salt);
}

function generateVaultCode() {
    return encode64(crypto.getRandomValues(new Uint8Array(32)));
}

async function privateWrappingKey(code) {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(code ?? "")) {
        throw Error("请输入这套仓库的 44 位加密密钥，或先生成并保存一份。");
    }
    return crypto.subtle.importKey("raw", decode64(code), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function accountRequest(data) {
    let response;
    try {
        response = await requestUrl({url: SERVICE + "/v1/account/connect", method: "POST",
            contentType: "application/json", body: JSON.stringify(data), throw: false});
    } catch {
        throw Error("无法连接 Blueee Notes 登录服务，请检查网络后重试。");
    }
    if (response.status === 200 || response.status === 202) return response.json;
    let errorCode;
    try { errorCode = response.json.error; } catch { /* A proxy may return a non-JSON response. */ }
    throw Object.assign(Error(ERRORS[errorCode] ?? "登录服务暂时不可用。"), {code: errorCode});
}

async function checkInvite(invite) {
    if (!invite) throw Error("请输入管理员给你的注册口令。");
    const {ticket} = await accountRequest({mode: "check_invite", invite});
    if (typeof ticket !== "string") throw Error("口令验证服务暂时不可用。");
    return ticket;
}

async function connectAccount({mode, account, vault, password, ticket, email, code, vaultCode}) {
    account = account.toLowerCase();
    if (!NAME.test(account) || !NAME.test(vault)) throw Error(ERRORS.invalid_request);
    if (password.length < 6 || password.length > 256) throw Error("请输入 6–256 个字符的密码。");
    const {proof, wrap} = await accountKeys(account, password);
    const data = {mode, account, vault, proof, ticket};
    if (mode === "register" || mode === "verify") {
        data.email = (email ?? "").trim().toLowerCase();
        if (!data.email || !data.email.includes("@")) throw Error(ERRORS.email_invalid);
    }
    if (mode === "verify") data.code = code;
    if (mode === "register" || mode === "create") {
        const privateKey = await privateWrappingKey(vaultCode);
        const key = crypto.getRandomValues(new Uint8Array(32));
        const salt = encode64(crypto.getRandomValues(new Uint8Array(16)));
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({
            name: "AES-GCM", iv: nonce, additionalData: wrappingContext(account, vault, salt, "v2"),
        }, privateKey, key);
        data.wrappedKey = ["v2", salt, encode64(nonce), encode64(new Uint8Array(encrypted))].join(".");
    }
    const result = await accountRequest(data);
    if (result.status) return result;
    const {token, wrappedKey} = result;
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw Error("登录服务返回无效会话。");
    const pair = {url: SERVICE, token, account, vault};
    const parts = wrappedKey.split(".");
    const version = parts.length === 4 ? parts.shift() : "v1";
    const [salt, nonce, ciphertext] = parts;
    const privateKey = version === "v2" ? await privateWrappingKey(vaultCode) : wrap;
    let key;
    try {
        key = await crypto.subtle.decrypt({
            name: "AES-GCM", iv: decode64(nonce), additionalData: wrappingContext(account, vault, salt, version),
        }, privateKey, decode64(ciphertext));
    } catch {
        throw Error("仓库的加密密钥不正确。");
    }
    if (key.byteLength !== 32) throw Error("仓库密钥无效。");
    return {...pair, key: encode64(new Uint8Array(key))};
}

function accountForm(parent, plugin, done) {
    const pair = plugin.state.pair;
    const lockedVault = Boolean(pair?.account);
    const root = parent.createEl("form", {cls: "simple-note-sync-account"});
    let step = "invite";
    let ticket;
    let action;
    const actions = new Setting(root).setName("账号操作");
    const fields = new Map();
    const buttons = {
        login: "连接 Blueee Notes", create: "新建并连接", invite: "验证口令",
        register: "发送验证码", verify: "验证邮箱", resume: "验证邮箱",
    };
    const show = (field, visible) => {
        field.row.settingEl.hidden = !visible;
        field.input.disabled = !visible;
        field.input.required = visible;
    };
    const setStep = next => {
        step = next;
        const visibleDetails = step !== "invite" && step !== "verify";
        for (const field of fields.values()) show(field, visibleDetails);
        show(email, step === "register" || step === "resume");
        show(invite, step === "invite");
        actions.settingEl.hidden = step === "invite";
        const needsKey = ["login", "register", "create"].includes(step);
        show(vaultCode, needsKey);
        vaultCode.input.required = needsKey && step !== "login";
        generate.buttonEl.hidden = step !== "register" && step !== "create";
        show(code, step === "verify" || step === "resume");
        submit.setText(buttons[step]);
    };
    actions.addDropdown(field => {
        action = field;
        field.addOption("login", "登录并连接已有仓库");
        if (!lockedVault) {
            field.addOption("register", "注册新账号");
            field.addOption("resume", "继续验证已申请的邮箱");
            field.addOption("create", "已有账号，新建远端仓库");
        }
        field.onChange(next => {
            feedback.empty();
            setStep(next);
        });
    });
    for (const [id, label, type, initial, autocomplete] of [
        ["account", "账号", "text", pair?.account ?? "", "username"],
        ["password", "密码", "password", "", "current-password"],
        ["vault", "远端仓库名", "text", pair?.vault ?? "main", "off"],
    ]) {
        const row = new Setting(root).setName(label);
        row.addText(field => {
            field.setValue(initial);
            const input = field.inputEl;
            input.type = type;
            input.autocomplete = autocomplete;
            input.setAttribute("aria-label", label);
            input.required = true;
            input.readOnly = lockedVault && id !== "password";
            fields.set(id, {row, input});
        });
    }
    const addField = (label, configure) => {
        const row = new Setting(root).setName(label);
        let input;
        row.addText(field => {
            input = field.inputEl;
            input.setAttribute("aria-label", label);
            configure(input);
        });
        return {row, input};
    };
    const email = addField("邮箱", input => {
        input.type = "email";
        input.autocomplete = "email";
    });
    const code = addField("邮件验证码", input => {
        input.inputMode = "numeric";
        input.maxLength = 6;
        input.autocomplete = "one-time-code";
    });
    const invite = addField("管理员注册口令", input => {
        input.type = "password";
        input.autocomplete = "off";
    });
    const vaultCode = addField("仓库加密密钥", input => {
        input.type = "password";
        input.autocomplete = "off";
    });
    vaultCode.row.setDesc("新仓库请生成并保存。换设备时需要同一份，服务器没有副本。");
    let generate;
    vaultCode.row.addButton(button => {
        generate = button.setButtonText("生成并复制").onClick(async () => {
            vaultCode.input.value = generateVaultCode();
            try {
                await navigator.clipboard.writeText(vaultCode.input.value);
                feedback.setText("已复制仓库密钥，请保存后再继续。");
            } catch {
                vaultCode.input.type = "text";
                vaultCode.input.select();
                feedback.setText("请手动复制并妥善保存仓库密钥。");
            }
        });
    });
    const feedback = root.createDiv({cls: "simple-note-sync-status", attr: {role: "status"}});
    const submit = root.createEl("button", {text: "连接 Blueee Notes", cls: "mod-cta", attr: {type: "submit"}});
    setStep("invite");
    const value = id => fields.get(id).input.value;
    root.addEventListener("submit", async event => {
        event.preventDefault();
        submit.disabled = true;
        action.setDisabled(true);
        feedback.dataset.state = "info";
        feedback.setText("正在处理…");
        try {
            if (step === "invite") {
                ticket = await checkInvite(invite.input.value);
                invite.input.value = "";
                action.setValue("login");
                setStep("login");
                feedback.setText("口令正确，可以选择注册或登录。");
                fields.get("account").input.focus();
                return;
            }
            const result = await plugin.connectAccount({
                mode: step === "resume" ? "verify" : step,
                account: value("account").trim().toLowerCase(),
                vault: value("vault").trim(),
                password: value("password"),
                ticket,
                email: email.input.value,
                code: code.input.value.trim(),
                vaultCode: vaultCode.input.value.trim(),
            });
            if (result === "verification_required") {
                setStep("verify");
                feedback.setText("验证码已发送到 " + email.input.value + "，请在这里输入，有效期 15 分钟。");
                code.input.focus();
            } else if (result === "approval_pending") {
                fields.get("password").input.value = code.input.value = "";
                action.setValue("login");
                setStep("login");
                feedback.setText(ERRORS.approval_pending);
            } else {
                fields.get("password").input.value = code.input.value = "";
                done();
            }
        } catch (error) {
            if (error.code === "invite_step_required") {
                ticket = undefined;
                setStep("invite");
                invite.input.focus();
            }
            feedback.dataset.state = "error";
            feedback.setText(error.message);
        } finally {
            submit.disabled = false;
            action.setDisabled(false);
        }
    });
}

module.exports = {accountForm, checkInvite, connectAccount, generateVaultCode};
