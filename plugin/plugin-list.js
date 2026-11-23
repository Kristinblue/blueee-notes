const {Modal, Notice} = require("obsidian");
const {cryptography} = require("./engine");

const CONTEXT = "blueee-notes-plugin-list-v1";
const ID = /^[a-zA-Z0-9_-]{1,100}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", {fatal: true});

async function localPlugins(vault, ownId) {
    const folder = vault.configDir + "/plugins";
    if (!await vault.adapter.exists(folder)) return [];
    const enabledPath = vault.configDir + "/community-plugins.json";
    const enabled = await vault.adapter.exists(enabledPath)
        ? new Set(JSON.parse(await vault.adapter.read(enabledPath))) : new Set();
    const {folders} = await vault.adapter.list(folder);
    const plugins = [];
    for (const directory of folders) {
        const id = directory.split("/").pop();
        if (id === ownId || !ID.test(id)) continue;
        try {
            const manifest = JSON.parse(await vault.adapter.read(directory + "/manifest.json"));
            if (manifest.id !== id || typeof manifest.name !== "string" || typeof manifest.version !== "string") continue;
            plugins.push({id, name: manifest.name.slice(0, 100), version: manifest.version.slice(0, 40), enabled: enabled.has(id)});
        } catch {
            // An incomplete installation has no usable manifest.
        }
    }
    return plugins.sort((left, right) => left.id.localeCompare(right.id));
}

function validateList(value) {
    if (!Array.isArray(value) || value.length > 500 || !value.every(plugin => plugin
        && typeof plugin.id === "string" && ID.test(plugin.id)
        && typeof plugin.name === "string" && plugin.name.length <= 100
        && typeof plugin.version === "string" && plugin.version.length <= 40
        && typeof plugin.enabled === "boolean")) throw Error("远端插件清单格式错误。");
    return value;
}

class PluginList extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        const pair = this.plugin.state.pair;
        this.setTitle("插件清单");
        this.contentEl.createEl("p", {text: "同步插件名称、版本和启用状态。需要的插件请在 Obsidian 市场安装。"});
        const fetch = this.contentEl.createEl("button", {text: "查看远端清单"});
        const publish = this.contentEl.createEl("button", {text: "上传本机清单"});
        const status = this.contentEl.createDiv({attr: {role: "status"}});
        const list = this.contentEl.createEl("ul");
        const run = async action => {
            fetch.disabled = publish.disabled = true;
            status.setText("处理中…");
            try {
                const local = validateList(await localPlugins(this.app.vault, this.plugin.manifest.id));
                const cipher = await cryptography(pair.key);
                await action(local, cipher);
            } catch (error) {
                status.setText(error.message);
            } finally {
                fetch.disabled = publish.disabled = false;
            }
        };
        fetch.addEventListener("click", () => run(async (local, cipher) => {
            const {encrypted} = await this.plugin.request(pair, "GET", "/v1/plugin-list");
            list.empty();
            if (!encrypted) {
                status.setText("远端还没有插件清单。");
                return;
            }
            const remote = validateList(JSON.parse(decoder.decode(await cipher.open(encrypted, CONTEXT))));
            const installed = new Map(local.map(item => [item.id, item]));
            status.setText("远端插件 " + remote.length + " 个");
            for (const item of remote) {
                const current = installed.get(item.id);
                const row = list.createEl("li");
                const localStatus = current
                    ? "本机 " + current.version + (current.enabled ? "，已启用" : "，未启用")
                    : "本机未安装";
                row.createEl("a", {text: item.name, href: "obsidian://show-plugin?id=" + encodeURIComponent(item.id)});
                row.createSpan({text: " · 远端 " + item.version + (item.enabled ? "，已启用" : "，未启用")
                    + " · " + localStatus});
            }
        }));
        publish.addEventListener("click", () => {
            if (publish.dataset.confirm !== "yes") {
                publish.dataset.confirm = "yes";
                publish.setText("确认替换远端清单");
                return;
            }
            publish.dataset.confirm = "";
            publish.setText("上传本机清单");
            void run(async (local, cipher) => {
                const encrypted = await cipher.seal(encoder.encode(JSON.stringify(local)), CONTEXT);
                await this.plugin.request(pair, "POST", "/v1/plugin-list", {encrypted});
                list.empty();
                status.setText("已上传 " + local.length + " 个插件的清单。");
            });
        });
        if (pair) fetch.click();
        else {
            new Notice("请先连接同步仓库。");
            this.close();
        }
    }
}

module.exports = {PluginList};
