const {Plugin, PluginSettingTab, Setting, Modal, FuzzySuggestModal, MarkdownView, TFile, TFolder, Notice, requestUrl, setIcon} = require("obsidian");
const {CONFLICTS, decode64, validPath, synchronize, inspectConflict, resolveConflict} = require("./engine");
const {ConflictPicker} = require("./conflicts");
const {accountForm, connectAccount, PasswordChange} = require("./account");
const {PluginList} = require("./plugin-list");

const DIRECTIONS = {
    pull: {name: "仅拉取", button: "开始拉取", activity: "正在下载远端改动…"},
    both: {name: "双向同步", button: "开始同步", activity: "正在上传和下载改动…"},
    push: {name: "仅推送", button: "开始推送", activity: "正在上传本机改动…"},
};

class FolderPicker extends FuzzySuggestModal {
    constructor(app, choose) {
        super(app);
        this.choose = choose;
        this.setPlaceholder("查找要同步的文件夹");
    }
    getItems() {
        return this.app.vault.getAllLoadedFiles().filter(file => file instanceof TFolder && validPath(file.path));
    }
    getItemText(folder) { return folder.path; }
    onChooseItem(folder) { this.choose({kind: "folder", path: folder.path}); }
}

class ScopePicker extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
        const active = app.workspace.getActiveFile();
        this.activePath = active && validPath(active.path) ? active.path : null;
        const last = plugin.state.last;
        this.folder = last?.kind === "folder" && app.vault.getAbstractFileByPath(last.path) instanceof TFolder
            ? last.path : null;
        this.kind = this.activePath ? "file" : this.folder ? "folder" : null;
        this.direction = "both";
        this.directionInputs = [];
        this.running = false;
        this.visible = false;
        this.fields = [];
    }

    onOpen() {
        this.visible = true;
        this.setTitle("同步笔记");
        this.modalEl.addClass("simple-note-sync-modal");
        const content = this.contentEl;
        const context = content.createDiv({cls: "simple-note-sync-context"});
        setIcon(context.createSpan({attr: {"aria-hidden": "true"}}), "archive");
        context.createSpan({text: this.app.vault.getName(), cls: "simple-note-sync-vault"});
        if (!this.plugin.state.pair) {
            context.createSpan({text: "未配对", cls: "simple-note-sync-connection"});
            content.createEl("p", {text: "配对一次后，就可以选择要同步的内容。"});
            const settings = content.createEl("button", {text: "打开配对设置", cls: "mod-cta"});
            settings.addEventListener("click", () => {
                this.close();
                this.app.setting.open();
                this.app.setting.openTabById(this.plugin.manifest.id);
            });
            return;
        }

        context.createSpan({text: "已配对", cls: "simple-note-sync-connection"});
        const autoSetting = new Setting(content).setName("自动同步")
            .setDesc(this.plugin.state.auto
                ? this.plugin.autoFeedback ?? "只同步当前打开的笔记"
                : "开启后同步当前打开的笔记");
        autoSetting
            .addToggle(toggle => toggle.setValue(this.plugin.state.auto).onChange(async value => {
                try {
                    await this.plugin.setAuto(value);
                    autoSetting.setDesc(value ? "只同步当前打开的笔记" : "开启后同步当前打开的笔记");
                } catch (error) {
                    toggle.setValue(this.plugin.state.auto);
                    new Notice(error.message);
                }
            }));
        const modes = content.createEl("fieldset", {cls: "simple-note-sync-direction"});
        modes.createEl("legend", {text: "同步方向"});
        const options = modes.createDiv({cls: "simple-note-sync-direction-options"});
        for (const [id, direction] of Object.entries(DIRECTIONS)) {
            const option = options.createEl("label");
            const radio = option.createEl("input", {attr: {type: "radio", name: "simple-note-sync-direction", value: id}});
            option.createSpan({text: direction.name});
            radio.checked = id === this.direction;
            radio.addEventListener("change", () => {
                this.direction = id;
                this.update();
            });
            this.directionInputs.push(radio);
        }
        const choices = content.createEl("fieldset", {cls: "simple-note-sync-choices"});
        choices.createEl("legend", {text: "同步范围"});
        this.addChoice(choices, "file", "file-text", "当前笔记", this.activePath ?? "先打开一篇笔记");
        this.folderText = this.addChoice(choices, "folder", "folder", "文件夹", this.folder ?? "含子文件夹");
        this.addChoice(choices, "vault", "files", "整个仓库", "同步此仓库的所有笔记和附件");

        const folderActions = content.createDiv({cls: "simple-note-sync-folder-actions"});
        this.pickFolder = folderActions.createEl("button", {text: "选择文件夹", attr: {type: "button"}});
        this.pickFolder.addEventListener("click", () => new FolderPicker(this.app, scope => {
            this.folder = scope.path;
            this.kind = "folder";
            this.update();
            this.primary.focus();
        }).open());
        this.status = content.createDiv({cls: "simple-note-sync-status", attr: {role: "status", "aria-live": "polite"}});
        const actions = content.createDiv({cls: "simple-note-sync-actions"});
        this.primary = actions.createEl("button", {text: "开始同步", cls: "mod-cta", attr: {type: "button"}});
        this.primary.addEventListener("click", () => this.run());
        this.pluginListButton = actions.createEl("button", {text: "插件同步", attr: {type: "button"}});
        this.pluginListButton.addEventListener("click", () => {
            if (this.running) return;
            this.close();
            new PluginList(this.app, this.plugin).open();
        });
        this.conflictLink = actions.createEl("button", {attr: {type: "button"}});
        this.conflictLink.addEventListener("click", () => {
            this.close();
            this.plugin.showConflicts();
        });
        this.update();
    }

    addChoice(parent, kind, icon, name, description) {
        const row = parent.createEl("label", {cls: "simple-note-sync-choice"});
        const input = row.createEl("input", {attr: {type: "radio", name: "simple-note-sync-scope", value: kind}});
        setIcon(row.createSpan({cls: "simple-note-sync-icon", attr: {"aria-hidden": "true"}}), icon);
        const wording = row.createSpan({cls: "simple-note-sync-wording"});
        wording.createSpan({text: name, cls: "simple-note-sync-choice-name"});
        const detail = wording.createSpan({text: description, cls: "simple-note-sync-detail"});
        input.addEventListener("change", () => {
            this.kind = kind;
            this.update();
        });
        this.fields.push({row, input, kind});
        return detail;
    }

    selectedScope() {
        if (this.kind === "file" && this.activePath) return {kind: "file", path: this.activePath};
        if (this.kind === "folder" && this.folder) return {kind: "folder", path: this.folder};
        if (this.kind === "vault") return {kind: "vault"};
        return null;
    }

    update() {
        const selected = this.selectedScope();
        for (const {row, input, kind} of this.fields) {
            input.checked = kind === this.kind;
            input.disabled = this.running || (kind === "file" && !this.activePath);
            row.toggleClass("is-selected", input.checked);
        }
        this.folderText.setText(this.folder ?? "含子文件夹");
        this.pickFolder.hidden = this.kind !== "folder";
        this.pickFolder.disabled = this.running;
        this.pickFolder.setText(this.folder ? "更换文件夹" : "选择文件夹");
        this.status.dataset.state = "info";
        for (const input of this.directionInputs) input.disabled = this.running;
        this.status.setText(this.kind === "folder" && !this.folder ? "请选择要同步的文件夹。"
            : this.kind === "file" ? "单篇只处理这一文件。"
                : this.direction === "pull" ? "下载所选范围的远端改动。"
                    : this.direction === "push" ? "上传所选范围的本机改动。"
                        : "上传和下载所选范围的改动。");
        this.primary.disabled = this.running || !selected;
        this.pluginListButton.disabled = this.running;
        const count = Object.keys(this.plugin.state.conflicts).length;
        this.conflictLink.hidden = count === 0;
        this.conflictLink.setText("处理冲突 · " + count);
        if (!this.running) this.primary.setText(DIRECTIONS[this.direction].button);
    }

    async run() {
        const scope = this.selectedScope();
        if (!scope || this.running) return;
        this.running = true;
        this.update();
        this.status.setText(DIRECTIONS[this.direction].activity);
        this.primary.setText("处理中…");
        const result = await this.plugin.sync(scope, {direction: this.direction, inline: () => this.visible});
        this.running = false;
        if (!this.visible) return;
        this.update();
        this.primary.setText(result.state === "error" ? "重试" : DIRECTIONS[this.direction].button);
        this.status.dataset.state = result.state;
        this.status.setText(result.message);
    }

    onClose() {
        this.visible = false;
        this.contentEl.empty();
    }
}

function parsePair(value) {
    const config = JSON.parse(value.trim());
    const url = new URL(config.url);
    const loopback = url.protocol === "http:" && url.hostname === "127.0.0.1";
    if ((!loopback && url.protocol !== "https:") || url.username || url.password || url.search || url.hash
        || !/^[A-Za-z0-9_-]{43}$/.test(config.token) || decode64(config.key).length !== 32) {
        throw Error("配对配置无效");
    }
    return {url: url.href.replace(/\/$/, ""), token: config.token, key: config.key};
}

class DeviceList extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    async onOpen() {
        this.setTitle("我的设备");
        const pair = this.plugin.state.pair;
        const status = this.contentEl.createDiv({attr: {role: "status"}});
        status.setText("正在读取设备…");
        try {
            const rows = await this.plugin.request(pair, "GET", "/v1/account/devices");
            status.setText(rows.length + " 台已验证设备");
            for (const device of rows) {
                const setting = new Setting(this.contentEl)
                    .setName(device.name + (device.current ? "（当前设备）" : ""))
                    .setDesc("首次登录 " + new Date(device.firstSeen * 1000).toLocaleString()
                        + " · 最近活动 " + new Date(device.lastSeen * 1000).toLocaleString()
                        + (device.active ? " · 会话有效" : " · 会话已过期"));
                if (!device.current) setting.addButton(button => {
                    let confirm = false;
                    button.setButtonText("退出设备").onClick(async () => {
                        if (!confirm) {
                            confirm = true;
                            button.setButtonText("确认退出");
                            return;
                        }
                        button.setDisabled(true);
                        try {
                            await this.plugin.request(pair, "POST", "/v1/account/devices/revoke", {id: device.id});
                            setting.settingEl.remove();
                            status.setText("设备已退出，下次登录须验证邮箱。");
                        } catch (error) {
                            status.setText(error.message);
                            button.setDisabled(false);
                        }
                    });
                });
            }
        } catch (error) {
            status.setText(error.message);
        }
    }

    onClose() { this.contentEl.empty(); }
}

class PairSettings extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }
    display() {
        this.containerEl.empty();
        this.containerEl.addClass("simple-note-sync-settings");
        const connected = Boolean(this.plugin.state.pair);
        const summary = this.containerEl.createDiv({cls: "simple-note-sync-settings-summary"});
        const icon = summary.createSpan({attr: {"aria-hidden": "true"}});
        setIcon(icon, connected ? "link" : "link-2-off");
        const connection = summary.createDiv();
        connection.createEl("strong", {text: connected ? "已配对" : "连接同步仓库"});
        connection.createDiv({text: connected ? this.app.vault.getName() : "先验证口令，再登录或注册账号"});

        const account = this.plugin.state.pair?.account;
        if (connected) {
            new Setting(this.containerEl).setName("笔记同步")
                .setDesc("选择范围，拉取、双向同步或推送笔记与附件。")
                .addButton(button => button.setButtonText("打开同步面板").onClick(() => {
                    this.plugin.openScopePicker();
                }));
            new Setting(this.containerEl).setName("插件同步")
                .setDesc("在设备间查看同一仓库的社区插件清单。")
                .addButton(button => button.setButtonText("打开插件清单").onClick(() => {
                    new PluginList(this.app, this.plugin).open();
                }));
        }
        if (account) {
            const pair = this.plugin.state.pair;
            const profile = new Setting(this.containerEl).setName("账号与仓库").setDesc(pair.account + " · " + pair.vault);
            profile.addButton(button => button.setButtonText("查看账号").onClick(async () => {
                button.setDisabled(true);
                try {
                    const data = await this.plugin.request(pair, "GET", "/v1/account/profile");
                    const view = new Modal(this.app);
                    view.setTitle("账号与仓库");
                    view.contentEl.createEl("p", {text: data.name + (data.email ? " · " + data.email : "")});
                    const list = view.contentEl.createEl("ul");
                    for (const name of data.vaults) {
                        list.createEl("li", {text: name + (name === pair.vault ? "（当前仓库）" : "")});
                    }
                    view.open();
                } catch (error) {
                    new Notice(error.message);
                } finally {
                    button.setDisabled(false);
                }
            }));
            new Setting(this.containerEl).setName("账号密码")
                .addButton(button => button.setButtonText("修改密码").onClick(() => {
                    new PasswordChange(this.app, this.plugin).open();
                }));
            new Setting(this.containerEl).setName("我的设备")
                .addButton(button => button.setButtonText("查看设备").onClick(() => {
                    new DeviceList(this.app, this.plugin).open();
                }));
            const details = this.containerEl.createEl("details");
            details.createEl("summary", {text: "更新账号登录"});
            accountForm(details, this.plugin, () => this.display());
            return;
        }
        if (!connected) accountForm(this.containerEl, this.plugin, () => this.display());

        const formRoot = this.containerEl.createEl("details");
        formRoot.createEl("summary", {text: connected ? "更新旧版配对配置" : "使用旧版配对配置"});
        if (connected) {
            new Setting(this.containerEl).setName("配对其他设备")
                .addButton(button => button.setButtonText("复制配对配置").onClick(async () => {
                    try {
                        await navigator.clipboard.writeText(JSON.stringify(this.plugin.state.pair));
                        new Notice("配对配置已复制");
                    } catch {
                        new Notice("无法访问剪贴板");
                    }
                }));
        }
        const field = formRoot.createEl("textarea", {
            cls: "simple-note-sync-pair-input", attr: {"aria-label": "配对配置", placeholder: "粘贴配对配置",
                rows: "3", spellcheck: "false", autocomplete: "off"},
        });
        const feedback = formRoot.createDiv({cls: "simple-note-sync-status", attr: {role: "status"}});
        const connect = formRoot.createEl("button", {text: "连接仓库", cls: "mod-cta", attr: {type: "button"}});
        connect.disabled = true;
        field.addEventListener("input", () => {
            connect.disabled = !field.value.trim();
        });
        connect.addEventListener("click", async () => {
            connect.disabled = field.disabled = true;
            feedback.dataset.state = "info";
            feedback.setText("正在检查连接…");
            try {
                if (this.plugin.busy) throw Error("请等待当前同步结束");
                let next;
                try {
                    next = parsePair(field.value);
                } catch {
                    throw Error("配对配置无法识别，请完整复制后再试。");
                }
                const state = this.plugin.state;
                if (state.pair && (state.pair.url !== next.url || state.pair.key !== next.key)) {
                    throw Error("请在一个新的本地仓库中连接另一个同步仓库");
                }
                await this.plugin.request(next, "GET", "/v1/manifest");
                await this.plugin.saveData({...state, pair: next});
                state.pair = next;
                this.display();
            } catch (error) {
                feedback.dataset.state = "error";
                feedback.setText(error.message);
                connect.disabled = field.disabled = false;
            }
        });
    }
}

module.exports = class SimpleNoteSync extends Plugin {
    async onload() {
        const saved = await this.loadData() ?? {};
        this.state = {
            pair: saved.pair ?? null,
            last: saved.last ?? null,
            lastDirection: Object.hasOwn(DIRECTIONS, saved.lastDirection) ? saved.lastDirection : "both",
            checkpoints: Object.assign(Object.create(null), saved.checkpoints),
            auto: saved.auto === true,
            device: typeof saved.device === "string" ? saved.device : crypto.randomUUID(),
            conflicts: Object.assign(Object.create(null), saved.conflicts),
        };
        this.busy = false;
        this.pending = new Set();
        this.applying = new Set();
        this.acknowledged = new Map();
        this.ackPending = new Map();
        const choose = () => this.openScopePicker();
        this.addRibbonIcon("arrow-up-down", "笔记同步", choose);
        this.addCommand({id: "choose-scope", name: "选择同步范围", callback: choose});
        this.addCommand({id: "repeat", name: "按上次范围同步", callback: () => {
            if (this.state.last) this.sync(this.state.last, {direction: this.state.lastDirection});
            else choose();
        }});
        this.addCommand({id: "plugin-list", name: "同步插件清单", callback: () => {
            new PluginList(this.app, this).open();
        }});
        this.addCommand({id: "conflicts", name: "处理同步冲突", callback: () => this.showConflicts()});
        this.registerEvent(this.app.workspace.on("file-open", file => this.queueAuto(file)));
        this.registerEvent(this.app.vault.on("modify", file => {
            if (file.path === this.app.workspace.getActiveFile()?.path && !this.applying.has(file.path)) this.queueAuto(file);
        }));
        this.registerDomEvent(document, "visibilitychange", () => this.queueAuto(this.app.workspace.getActiveFile()));
        this.registerDomEvent(window, "online", () => this.queueAuto(this.app.workspace.getActiveFile()));
        this.registerInterval(window.setInterval(() => {
            const file = this.app.workspace.getActiveFile();
            if (this.isAutoNote(file)) this.pending.add(file.path);
            if (!this.autoTimer) void this.flushAuto();
        }, 6000));
        this.app.workspace.onLayoutReady(() => this.queueAuto(this.app.workspace.getActiveFile()));
        this.pairingTab = new PairSettings(this.app, this);
        this.addSettingTab(this.pairingTab);
    }

    onunload() { window.clearTimeout(this.autoTimer); }

    openScopePicker() {
        if (this.busy) new Notice("正在同步，请稍候");
        else new ScopePicker(this.app, this).open();
    }

    async connectAccount(values) {
        if (this.busy) throw Error("请等待当前同步结束");
        const current = this.state.pair;
        if (current && (!current.account || current.account !== values.account || current.vault !== values.vault
            || values.mode !== "login")) throw Error("请在新的本地仓库中连接另一个远端仓库。");
        this.busy = true;
        try {
            const {legacyWrap, ...pair} = await connectAccount({...values, existingKey: current?.key ?? values.existingKey});
            if (pair.status) return pair.status;
            if (current && current.key !== pair.key) throw Error("远端仓库密钥已变更，无法安全重新连接。");
            if (legacyWrap) await this.request(pair, "POST", "/v1/account/upgrade-wrap", legacyWrap);
            await this.saveData({...this.state, pair});
            this.state.pair = pair;
        } finally {
            this.busy = false;
        }
        this.queueAuto(this.app.workspace.getActiveFile());
    }

    async setAuto(value) {
        if (this.busy) throw Error("请等待当前同步结束");
        await this.saveData({...this.state, auto: value});
        this.state.auto = value;
        this.autoFeedback = undefined;
        if (value) this.queueAuto(this.app.workspace.getActiveFile());
        else {
            this.pending.clear();
            window.clearTimeout(this.autoTimer);
            this.autoTimer = undefined;
        }
    }

    isAutoNote(file) {
        return this.state.auto && this.state.pair && file instanceof TFile && file.extension.toLowerCase() === "md"
            && validPath(file.path);
    }

    queueAuto(file) {
        if (!this.isAutoNote(file)) return;
        this.pending.add(file.path);
        window.clearTimeout(this.autoTimer);
        this.autoTimer = window.setTimeout(() => {
            this.autoTimer = undefined;
            void this.flushAuto();
        }, 1400);
    }

    async flushAuto() {
        if (!this.state.auto || this.busy || this.autoRunning || document.hidden || navigator.onLine === false) return;
        this.autoRunning = true;
        try {
            for (const path of [...this.pending]) {
                if (!this.state.auto || document.hidden || this.autoTimer || this.busy) break;
                this.pending.delete(path);
                if (this.state.conflicts[path]) continue;
                const result = await this.sync({kind: "file", path}, {automatic: true});
                this.autoFeedback = result.state === "success" ? "当前笔记 · " + result.message : result.message;
                if (result.state === "error") {
                    this.pending.add(path);
                    break;
                }
            }
        } finally {
            this.autoRunning = false;
        }
    }

    showConflicts() {
        if (Object.keys(this.state.conflicts).length) new ConflictPicker(this.app, this).open();
        else new Notice("没有待处理的同步冲突");
    }

    async request(pair, method, route, body) {
        let response;
        try {
            response = await requestUrl({
                url: pair.url + route, method, headers: {Authorization: "Bearer " + pair.token},
                ...(body === undefined ? {} : {contentType: "application/json", body: JSON.stringify(body)}),
                throw: false,
            });
        } catch {
            throw Error("无法连接同步服务器，请检查网络后重试");
        }
        const messages = {401: "登录已失效，请打开 Blueee Notes 设置重新登录或配对", 409: "同步期间远端有更新，请重试", 413: "文件太大"};
        if (response.status !== 200) {
            const error = Error(messages[response.status] ?? "服务器错误 " + response.status);
            error.status = response.status;
            throw error;
        }
        return response.json;
    }

    fileStore() {
        const {vault, fileManager} = this.app;
        const assertSavedEditor = (file, bytes) => {
            const view = this.app.workspace.getActiveViewOfType(MarkdownView);
            if (view?.file?.path !== file.path || (view.getMode() !== "source") || !view.editor) return;
            const onDisk = new TextDecoder().decode(bytes).replace(/\r\n/g, "\n");
            if (view.editor.getValue().replace(/\r\n/g, "\n") !== onDisk) {
                throw Error("当前笔记还有未保存的改动，请稍候再试。");
            }
        };
        const ensureParent = async path => {
            let parent = "";
            for (const folder of path.split("/").slice(0, -1)) {
                parent = parent ? parent + "/" + folder : folder;
                if (!vault.getAbstractFileByPath(parent)) await vault.createFolder(parent);
            }
        };
        return {
            paths: () => vault.getFiles().map(file => file.path),
            read: async path => {
                const file = vault.getAbstractFileByPath(path);
                if (!(file instanceof TFile)) return null;
                const bytes = await vault.readBinary(file);
                assertSavedEditor(file, bytes);
                return bytes;
            },
            write: async (path, data) => {
                const file = vault.getAbstractFileByPath(path);
                this.applying.add(path);
                try {
                    if (file instanceof TFile && file.extension.toLowerCase() === "md") {
                        assertSavedEditor(file, await vault.readBinary(file));
                    }
                    if (data === null) {
                        if (file instanceof TFile) await fileManager.trashFile(file);
                    } else if (file instanceof TFile) {
                        await vault.modifyBinary(file, data);
                    } else {
                        await ensureParent(path);
                        await vault.createBinary(path, data);
                    }
                } finally {
                    this.applying.delete(path);
                }
            },
            conflict: async (path, remote, revision) => {
                const directory = CONFLICTS + "/远端版本-" + revision + "/" + path;
                const target = remote === null ? directory + ".远端已删除.md" : directory;
                if (!vault.getAbstractFileByPath(target)) {
                    await ensureParent(target);
                    if (remote === null) await vault.create(target, "远端删除了这篇笔记。本机版本仍在原位置。");
                    else await vault.createBinary(target, remote);
                }
                if (this.state.conflicts[path] !== revision) {
                    const before = this.state.conflicts[path];
                    this.state.conflicts[path] = revision;
                    try {
                        await this.saveData(this.state);
                    } catch (error) {
                        if (before) this.state.conflicts[path] = before;
                        else delete this.state.conflicts[path];
                        throw error;
                    }
                }
            },
        };
    }

    session(pair) {
        return {
            key: pair.key,
            checkpoints: this.state.checkpoints,
            store: this.fileStore(),
            request: (method, route, body) => this.request(pair, method, route, body),
            persist: (path, entry, id) => this.recordRevision(path, entry, id),
        };
    }

    async recordRevision(path, entry, id) {
        const {checkpoints, conflicts} = this.state;
        const before = checkpoints[path];
        const conflict = conflicts[path];
        if (conflict || (entry.revision > 0 && (before?.hash !== entry.hash || before?.revision !== entry.revision))) {
            checkpoints[path] = entry;
            delete conflicts[path];
            try {
                await this.saveData(this.state);
            } catch (error) {
                if (before) checkpoints[path] = before;
                else delete checkpoints[path];
                if (conflict) conflicts[path] = conflict;
                throw error;
            }
        }
        const ack = this.acknowledged.get(id);
        if (entry.revision > 0 && (!ack || ack.revision !== entry.revision || Date.now() - ack.time > 60000)) {
            this.ackPending.set(id, entry.revision);
        }
    }

    async flushAcknowledgements(pair) {
        for (const [id, revision] of [...this.ackPending]) {
            try {
                await this.request(pair, "POST", "/v1/ack", {id, revision, device: this.state.device});
                this.acknowledged.set(id, {revision, time: Date.now()});
                if (this.ackPending.get(id) === revision) this.ackPending.delete(id);
            } catch {
                break;
            }
        }
    }

    async readConflict(path) {
        if (this.busy) throw Error("正在同步，请稍候");
        if (!this.state.pair) throw Error("请先连接同步仓库");
        return inspectConflict({path, ...this.session(this.state.pair)});
    }

    async finishConflict(snapshot, option, text) {
        if (this.busy) throw Error("正在同步，请稍候");
        const pair = this.state.pair;
        if (!pair) throw Error("请先连接同步仓库");
        this.busy = true;
        try {
            await resolveConflict({snapshot, option, text, ...this.session(pair)});
            await this.flushAcknowledgements(pair);
        } finally {
            this.busy = false;
        }
    }

    async sync(scope, {direction = "both", inline = () => false, automatic = false} = {}) {
        const report = (state, message) => {
            if (!inline() && (!automatic || state === "warning")) new Notice(message, 7000);
            return {state, message};
        };
        if (this.busy) return report("error", "正在同步，请稍候");
        const {pair} = this.state;
        if (!pair) {
            return report("error", "请先在「笔记同步」设置里连接仓库");
        }
        this.busy = true;
        const progress = inline() || automatic ? null : new Notice("正在同步…", 0);
        try {
            if (!automatic) {
                this.state.last = scope;
                this.state.lastDirection = direction;
                await this.saveData(this.state);
            }
            const result = await synchronize({scope, direction, ...this.session(pair)});
            await this.flushAcknowledgements(pair);
            const skipped = result.skipped ? ` · 跳过 ${result.skipped} 个超过 40 MiB 的文件` : "";
            const summary = direction === "pull" ? `下载 ${result.downloaded}${skipped}`
                : direction === "push" ? `上传 ${result.uploaded}${skipped}`
                    : `上传 ${result.uploaded} · 下载 ${result.downloaded}${result.merged ? " · 合并 " + result.merged : ""}${skipped}`;
            return result.conflicts
                ? report("warning", direction === "push"
                    ? `${summary} · 跳过 ${result.conflicts} 项冲突，双向同步可查看远端版本`
                    : `${summary} · ${result.conflicts} 项冲突待处理`)
                : report(result.skipped ? "warning" : "success",
                    result.uploaded || result.downloaded || result.merged || result.skipped
                        ? "完成 · " + summary : "此方向没有待处理的改动。");
        } catch (error) {
            return report("error", "同步暂停：" + error.message);
        } finally {
            progress?.hide();
            this.busy = false;
        }
    }
};
