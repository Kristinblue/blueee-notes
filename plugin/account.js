const {requestUrl, Setting, Modal, Notice} = require("obsidian");
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
    login_invalid: "账号或密码错误，或账号已被停用。忘记密码请联系管理员。",
    vault_missing: "这个账号下没有该仓库，请核对名称或选择新建远端仓库。",
    vault_exists: "这个远端仓库已存在，请选择登录。",
    device_required: "当前插件版本需要更新后才能登录。",
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

async function wrapVaultKey(wrap, account, vault, key) {
    const salt = encode64(crypto.getRandomValues(new Uint8Array(16)));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({
        name: "AES-GCM", iv: nonce, additionalData: wrappingContext(account, vault, salt, "v1"),
    }, wrap, key);
    return [salt, encode64(nonce), encode64(new Uint8Array(encrypted))].join(".");
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

async function connectAccount({mode, account, vault, password, ticket, email, code, existingKey, legacyCode, device, deviceName}) {
    account = account.toLowerCase();
    if (!NAME.test(account) || !NAME.test(vault)) throw Error(ERRORS.invalid_request);
    if (password.length < 6 || password.length > 256) throw Error("请输入 6–256 个字符的密码。");
    const {proof, wrap} = await accountKeys(account, password);
    if (["register", "create"].includes(mode) && password.length < 12) throw Error("新密码至少需要 12 个字符。");
    const data = {mode, account, vault, proof, ticket, device, deviceName};
    if (mode === "register" || mode === "verify") {
        data.email = (email ?? "").trim().toLowerCase();
        if (!data.email || !data.email.includes("@")) throw Error(ERRORS.email_invalid);
    }
    if (code) data.code = code;
    if (mode === "register" || mode === "create") {
        data.wrappedKey = await wrapVaultKey(wrap, account, vault, crypto.getRandomValues(new Uint8Array(32)));
    }
    const result = await accountRequest(data);
    if (result.status) return result;
    const {token, wrappedKey} = result;
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw Error("登录服务返回无效会话。");
    const pair = {url: SERVICE, token, account, vault};
    const parts = wrappedKey.split(".");
    const version = parts.length === 4 ? parts.shift() : "v1";
    const [salt, nonce, ciphertext] = parts;
    if (version === "v2") {
        if (!existingKey && !legacyCode) {
            throw Object.assign(Error("首次连接旧仓库需要导入这台电脑保存的密钥。"), {code: "legacy_key_required"});
        }
        let oldKey;
        try {
            if (existingKey) {
                oldKey = decode64(existingKey);
            } else {
                const recovery = await crypto.subtle.importKey("raw", decode64(legacyCode),
                    "AES-GCM", false, ["decrypt"]);
                oldKey = new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: decode64(nonce),
                    additionalData: wrappingContext(account, vault, salt, "v2")}, recovery, decode64(ciphertext)));
            }
            if (oldKey.byteLength !== 32) throw Error("Invalid key length");
        } catch {
            throw Object.assign(Error("原仓库密钥不正确，请重新复制后再试。"), {code: "legacy_key_required"});
        }
        return {...pair, key: encode64(oldKey), legacyWrap: password.length >= 12 ? {
            previous: wrappedKey, wrapped: await wrapVaultKey(wrap, account, vault, oldKey),
        } : null};
    }
    let key;
    try {
        key = await crypto.subtle.decrypt({
            name: "AES-GCM", iv: decode64(nonce), additionalData: wrappingContext(account, vault, salt, version),
        }, wrap, decode64(ciphertext));
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
    let needsDeviceCode = false;
    let needsLegacyKey = false;
    const deviceStorage = "blueee-notes-device-v1";
    let device = localStorage.getItem(deviceStorage);
    if (!device) {
        device = generateVaultCode();
        localStorage.setItem(deviceStorage, device);
    }
    const deviceName = navigator.userAgent.match(/Android|iPhone|iPad|Windows|Macintosh|Linux/)?.[0] ?? "Obsidian";
    let action;
    const actions = new Setting(root).setName("账号操作");
    const fields = new Map();
    const buttons = {
        login: "连接 Blueee Notes", create: "新建并连接", invite: "验证口令",
        register: "发送验证码", verify: "验证邮箱", resume: "验证邮箱",
    };
    const show = (field, visible) => {
        field.row.settingEl.hidden = !visible;
        field.row.settingEl.style.setProperty("display", visible ? "" : "none", visible ? "" : "important");
        field.input.disabled = !visible;
        field.input.required = visible;
    };
    const setStep = next => {
        step = next;
        const visibleDetails = step !== "invite" && step !== "verify";
        for (const field of fields.values()) show(field, visibleDetails);
        show(email, step === "register" || step === "resume");
        show(invite, step === "invite");
        show(confirmPassword, step === "register");
        show(legacyKey, visibleDetails && needsLegacyKey);
        show(code, (visibleDetails && needsDeviceCode) || step === "verify" || step === "resume");
        actions.settingEl.hidden = step === "invite";
        actions.settingEl.style.setProperty("display", step === "invite" ? "none" : "", step === "invite" ? "important" : "");
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
            needsDeviceCode = false;
            needsLegacyKey = false;
            code.input.value = "";
            legacyKey.input.value = "";
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
    const confirmPassword = addField("确认密码", input => {
        input.type = "password";
        input.autocomplete = "new-password";
    });
    fields.get("password").input.addEventListener("input", () => {
        if (step !== "register") return;
        const password = fields.get("password").input.value;
        const varieties = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(pattern => pattern.test(password)).length;
        confirmPassword.row.setDesc(password.length < 12 ? "密码强度：弱，至少输入 12 个字符"
            : password.length >= 16 || varieties >= 3 ? "密码强度：强" : "密码强度：一般");
    });
    const email = addField("邮箱", input => {
        input.type = "email";
        input.autocomplete = "email";
    });
    const legacyKey = addField("原仓库密钥（仅首次迁移）", input => {
        input.type = "password";
        input.autocomplete = "off";
        input.spellcheck = false;
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
            if (step === "register" && value("password") !== confirmPassword.input.value) {
                throw Error("两次输入的密码不一致。");
            }
            const result = await plugin.connectAccount({
                mode: step === "resume" ? "verify" : step,
                account: value("account").trim().toLowerCase(),
                vault: value("vault").trim(),
                password: value("password"),
                ticket,
                email: email.input.value,
                code: code.input.value.trim(),
                device, deviceName,
                legacyCode: legacyKey.input.value.trim(),
            });
            if (result === "device_verification_required") {
                needsDeviceCode = true;
                needsLegacyKey = false;
                setStep(step);
                feedback.setText("请输入邮箱验证码，验证这台设备。");
                code.input.focus();
            } else if (result === "verification_required") {
                setStep("verify");
                feedback.setText("验证码已发送到 " + email.input.value + "，请在这里输入，有效期 15 分钟。");
                code.input.focus();
            } else if (result === "approval_pending") {
                fields.get("password").input.value = code.input.value = "";
                action.setValue("login");
                setStep("login");
                feedback.setText(ERRORS.approval_pending);
            } else {
                fields.get("password").input.value = code.input.value = legacyKey.input.value = "";
                done();
            }
        } catch (error) {
            if (error.code === "legacy_key_required") {
                needsLegacyKey = true;
                needsDeviceCode = false;
                code.input.value = "";
                setStep("login");
                legacyKey.input.focus();
            }
            if (error.code === "invite_step_required") {
                ticket = undefined;
                needsLegacyKey = false;
                needsDeviceCode = false;
                code.input.value = "";
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

class PasswordChange extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        this.setTitle("修改密码");
        const pair = this.plugin.state.pair;
        const form = this.contentEl.createEl("form");
        const fields = {};
        for (const [id, label] of [["old", "旧密码"], ["next", "新密码"], ["again", "确认新密码"], ["code", "邮件验证码"]]) {
            const item = new Setting(form).setName(label);
            item.addText(field => {
                const input = field.inputEl;
                input.type = id === "code" ? "text" : "password";
                input.required = id !== "code";
                input.disabled = id === "code";
                input.autocomplete = id === "old" ? "current-password" : id === "code" ? "one-time-code" : "new-password";
                if (id === "code") {
                    input.maxLength = 6;
                    input.inputMode = "numeric";
                    item.settingEl.hidden = true;
                }
                input.setAttribute("aria-label", label);
                fields[id] = {input, item};
            });
        }
        const status = form.createDiv({attr: {role: "status"}});
        fields.next.input.addEventListener("input", () => {
            const password = fields.next.input.value;
            const varieties = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(pattern => pattern.test(password)).length;
            fields.next.item.setDesc(password.length < 12 ? "密码强度：弱" :
                (password.length >= 16 || varieties >= 3 ? "密码强度：强" : "密码强度：一般"));
        });
        const submit = form.createEl("button", {text: "发送验证码", cls: "mod-cta", attr: {type: "submit"}});
        let change;
        form.addEventListener("submit", async event => {
            event.preventDefault();
            submit.disabled = true;
            try {
                if (!change) {
                    const password = fields.next.input.value;
                    if (password.length < 12 || password.length > 256) throw Error("新密码需要 12–256 个字符。");
                    if (password !== fields.again.input.value) throw Error("两次输入的新密码不一致。");
                    if (password === fields.old.input.value) throw Error("新密码需要与旧密码不同。");
                    const previous = await accountKeys(pair.account, fields.old.input.value);
                    const next = await accountKeys(pair.account, password);
                    const {vaults} = await this.plugin.request(pair, "POST", "/v1/account/password",
                        {mode: "prepare", oldProof: previous.proof});
                    const updated = {};
                    for (const [slug, wrapped] of Object.entries(vaults)) {
                        const [salt, iv, body] = wrapped.split(".");
                        const context = wrappingContext(pair.account, slug, salt, "v1");
                        const key = await crypto.subtle.decrypt({name: "AES-GCM", iv: decode64(iv),
                            additionalData: context}, previous.wrap, decode64(body));
                        const nonce = crypto.getRandomValues(new Uint8Array(12));
                        const renewed = await crypto.subtle.encrypt({name: "AES-GCM", iv: nonce,
                            additionalData: context}, next.wrap, key);
                        updated[slug] = {old: wrapped, new: [salt, encode64(nonce), encode64(new Uint8Array(renewed))].join(".")};
                    }
                    change = {mode: "commit", oldProof: previous.proof, newProof: next.proof, vaults: updated};
                    for (const id of ["old", "next", "again"]) {
                        fields[id].input.value = "";
                        fields[id].input.disabled = true;
                    }
                    fields.code.input.disabled = false;
                    fields.code.input.required = true;
                    fields.code.item.settingEl.hidden = false;
                    fields.code.input.focus();
                    status.setText("验证码已发送，请检查邮箱。");
                    submit.setText("确认修改密码");
                } else {
                    await this.plugin.request(pair, "POST", "/v1/account/password",
                        {...change, code: fields.code.input.value.trim()});
                    new Notice("密码已更新。请在 Blueee Notes 设置中重新登录。");
                    this.close();
                }
            } catch (error) {
                status.setText(error.message);
            } finally {
                submit.disabled = false;
            }
        });
    }

    onClose() { this.contentEl.empty(); }
}

module.exports = {accountForm, checkInvite, connectAccount, generateVaultCode, PasswordChange, accountKeys, wrappingContext};
