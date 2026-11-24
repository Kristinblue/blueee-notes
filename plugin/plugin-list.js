const {Modal, Notice} = require("obsidian");
const {cryptography} = require("./engine");

const CONTEXT = "blueee-notes-plugin-list-v1";
const ID = /^[a-zA-Z0-9_-]{1,100}$/;
const MAX_CONFIG = 256 * 1024;
const MAX_TOTAL = 1536 * 1024;
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
    let configBytes = 0;
    for (const directory of folders) {
        const id = directory.split("/").pop();
        if (id === ownId || !ID.test(id)) continue;
        try {
            const manifest = JSON.parse(await vault.adapter.read(directory + "/manifest.json"));
            if (manifest.id !== id || typeof manifest.name !== "string" || typeof manifest.version !== "string") continue;
            const plugin = {id, name: manifest.name.slice(0, 100), version: manifest.version.slice(0, 40), enabled: enabled.has(id)};
            const configPath = directory + "/data.json";
            if (await vault.adapter.exists(configPath)) {
                const config = await vault.adapter.read(configPath);
                if (config.length <= MAX_CONFIG && configBytes + config.length <= MAX_TOTAL) {
                    try {
                        JSON.parse(config);
                        plugin.config = config;
                        configBytes += config.length;
                    } catch {
                        // Ignore a broken data.json instead of uploading it.
                    }
                }
            }
            plugins.push(plugin);
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
        && typeof plugin.enabled === "boolean"
        && (plugin.config === undefined || (typeof plugin.config === "string" && plugin.config.length <= MAX_CONFIG)))) {
        throw Error("远端插件清单格式错误。");
    }
    let total = 0;
    for (const plugin of value) {
        if (plugin.config === undefined) continue;
        try {
            JSON.parse(plugin.config);
        } catch {
            throw Error("远端插件配置不是有效 JSON。");
        }
        total += plugin.config.length;
    }
    if (total > MAX_TOTAL) throw Error("远端插件配置过大。");
    return value;
}

class PluginList extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        const pair = this.plugin.state.pair;
        this.setTitle("插件清单和配置");
        this.contentEl.createEl("p", {
            text: "同步插件名称、版本、启用状态和 data.json 配置。插件程序仍从 Obsidian 市场安装，不会传输插件代码。配置可能包含密钥，只应同步到同一账号的可信设备。",
        });
        const sync = this.contentEl.createEl("button", {text: "同步到本机"});
        const publish = this.contentEl.createEl("button", {text: "上传本机清单和配置"});
        const status = this.contentEl.createDiv({attr: {role: "status"}});
        const list = this.contentEl.createEl("ul");
        const run = async action => {
            sync.disabled = publish.disabled = true;
            status.setText("处理中…");
            try {
                const local = validateList(await localPlugins(this.app.vault, this.plugin.manifest.id));
                const cipher = await cryptography(pair.key);
                await action(local, cipher);
            } catch (error) {
                status.setText(error.message);
            } finally {
                sync.disabled = publish.disabled = false;
            }
        };
        sync.addEventListener("click", () => run(async (local, cipher) => {
            const {encrypted} = await this.plugin.request(pair, "GET", "/v1/plugin-list");
            list.empty();
            if (!encrypted) {
                status.setText("远端还没有插件清单。先点「上传本机清单和配置」。");
                return;
            }
            const remote = validateList(JSON.parse(decoder.decode(await cipher.open(encrypted, CONTEXT))));
            const installed = new Map(local.map(item => [item.id, item]));
            let applied = 0;
            let toggled = 0;
            let mismatched = 0;
            let missing = 0;
            for (const item of remote) {
                if (item.id === this.plugin.manifest.id) continue;
                const current = installed.get(item.id);
                if (!current) {
                    missing++;
                    continue;
                }
                const sameVersion = current.version === item.version;
                if (item.config && sameVersion) {
                    try {
                        await this.app.vault.adapter.write(
                            this.app.vault.configDir + "/plugins/" + item.id + "/data.json", item.config);
                        applied++;
                    } catch {
                        mismatched++;
                    }
                } else if (item.config) {
                    mismatched++;
                }
                try {
                    if (current.enabled !== item.enabled) {
                        if (item.enabled) await this.app.plugins.enablePlugin(item.id);
                        else await this.app.plugins.disablePlugin(item.id);
                        toggled++;
                    } else if (item.config && sameVersion && current.enabled) {
                        await this.app.plugins.disablePlugin(item.id);
                        await this.app.plugins.enablePlugin(item.id);
                    }
                } catch {
                    // The config is written; the plugin may need a manual reload.
                }
            }
            for (const item of remote) {
                if (item.id === this.plugin.manifest.id) continue;
                const current = installed.get(item.id);
                const row = list.createEl("li");
                row.createEl("a", {
                    text: item.name,
                    href: "obsidian://show-plugin?id=" + encodeURIComponent(item.id),
                });
                const parts = ["远端 " + item.version + (item.enabled ? "，已启用" : "，未启用")];
                if (!current) {
                    parts.push("本机未安装，点名字去市场安装");
                } else {
                    parts.push("本机 " + current.version + (current.enabled ? "，已启用" : "，未启用"));
                    if (item.config) parts.push(current.version === item.version ? "配置已应用" : "版本不同，未应用配置");
                }
                row.createSpan({text: " · " + parts.join(" · ")});
            }
            status.setText(`已应用 ${applied} 个配置，调整 ${toggled} 个启用状态；${missing} 个未安装，${mismatched} 个版本不同或配置写入失败。`);
            if (applied) new Notice("插件配置已同步；未安装的插件请点名字去市场安装。");
        }));
        publish.addEventListener("click", () => {
            if (publish.dataset.confirm !== "yes") {
                publish.dataset.confirm = "yes";
                publish.setText("确认替换远端清单和配置");
                return;
            }
            publish.dataset.confirm = "";
            publish.setText("上传本机清单和配置");
            void run(async (local, cipher) => {
                const encrypted = await cipher.seal(encoder.encode(JSON.stringify(local)), CONTEXT);
                await this.plugin.request(pair, "POST", "/v1/plugin-list", {encrypted});
                list.empty();
                const configured = local.filter(item => item.config).length;
                status.setText(`已上传 ${local.length} 个插件，其中 ${configured} 个带配置。`);
            });
        });
        if (!pair) {
            new Notice("请先连接同步仓库。");
            this.close();
        }
    }
}

module.exports = {PluginList};
