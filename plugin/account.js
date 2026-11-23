const {requestUrl, Setting} = require("obsidian");
const {encode64, decode64} = require("./engine");

const SERVICE = "https://blueee.cn:8443/simple-sync";
const NAME = /^[a-z0-9][a-z0-9_-]{2,39}$/;
const encoder = new TextEncoder();

const ERRORS = {
    invalid_request: "账号或远端仓库名需要 3–40 个小写字母、数字、横线或下划线。",
    registration_closed: "服务器还没有开放注册，请联系管理员。",
    invite_invalid: "注册口令错误或已更换。",
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

async function connectAccount({mode, account, vault, password, invite}) {
    if (!NAME.test(account) || !NAME.test(vault)) throw Error(ERRORS.invalid_request);
    if (password.length < 12 || password.length > 256) throw Error("请输入 12–256 个字符的密码。");
    if (mode === "register" && !invite) throw Error("请输入管理员给你的注册口令。");
    const {proof, wrap} = await accountKeys(account, password);
    const data = {mode, account, vault, proof};
    if (mode === "register") data.invite = invite;
    if (mode !== "login") {
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
    new Setting(root).setName("账号操作").addDropdown(field => {
        field.addOption("login", "登录并连接已有仓库");
        if (!lockedVault) {
            field.addOption("register", "用口令注册并创建首个仓库");
            field.addOption("create", "已有账号，新建远端仓库");
        }
        field.onChange(mode => {
            form.mode = mode;
            inviteRow.settingEl.hidden = mode !== "register";
            invite.required = mode === "register";
        });
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
    let invite;
    const inviteRow = new Setting(root).setName("管理员注册口令").addText(field => {
        invite = field.inputEl;
        invite.type = "password";
        invite.autocomplete = "off";
        invite.setAttribute("aria-label", "管理员注册口令");
    });
    inviteRow.settingEl.hidden = true;
    const feedback = root.createDiv({cls: "simple-note-sync-status", attr: {role: "status"}});
    const submit = root.createEl("button", {text: "连接 Blueee Notes", cls: "mod-cta", attr: {type: "submit"}});
    root.addEventListener("submit", async event => {
        event.preventDefault();
        submit.disabled = true;
        feedback.dataset.state = "info";
        feedback.setText("正在连接…");
        try {
            await plugin.connectAccount({
                mode: form.mode,
                account: inputs.account.value.trim(),
                vault: inputs.vault.value.trim(),
                password: inputs.password.value,
                invite: invite.value,
            });
            inputs.password.value = invite.value = "";
            done();
        } catch (error) {
            feedback.dataset.state = "error";
            feedback.setText(error.message);
        } finally {
            submit.disabled = false;
        }
    });
}

module.exports = {accountForm, connectAccount};
