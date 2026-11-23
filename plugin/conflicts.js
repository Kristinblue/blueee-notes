const {FuzzySuggestModal, Modal, Notice} = require("obsidian");
const {markdown, mergeMarkdown} = require("./engine");

class ConflictEditor extends Modal {
    constructor(app, plugin, snapshot) {
        super(app);
        this.plugin = plugin;
        this.snapshot = snapshot;
    }

    onOpen() {
        const {path, local, base, remote} = this.snapshot;
        this.setTitle("解决同步冲突");
        this.modalEl.addClass("simple-note-sync-conflict");
        this.contentEl.createEl("p", {text: path});
        const blocks = /\.md$/i.test(path) ? mergeMarkdown(local, base, remote) : null;
        const groups = blocks?.filter(block => block.conflict);
        if (groups?.length) {
            for (const {conflict} of groups) {
                this.showVersions(conflict.a.join(""), conflict.o.join(""), conflict.b.join(""));
            }
        } else if (/\.md$/i.test(path)) {
            this.showVersions(markdown(local), markdown(base), markdown(remote));
        }
        let editor;
        if (/\.md$/i.test(path) && (markdown(local) !== null || markdown(remote) !== null)) {
            this.contentEl.createEl("div", {text: "手动合并结果", cls: "simple-note-sync-choice-name"});
            editor = this.contentEl.createEl("textarea", {
                attr: {"aria-label": "手动合并结果", rows: "7", spellcheck: "false"},
            });
            editor.value = blocks
                ? blocks.flatMap(block => block.ok ?? block.conflict.a).join("")
                : markdown(local) ?? markdown(remote) ?? "";
            this.contentEl.createEl("p", {text: "编辑框预填本机的冲突段。保存前可把需要的远端内容合进来。",
                cls: "simple-note-sync-detail"});
        }
        const status = this.contentEl.createDiv({cls: "simple-note-sync-status", attr: {role: "status"}});
        const actions = this.contentEl.createDiv({cls: "simple-note-sync-resolution-actions"});
        const buttons = [];
        for (const [option, label] of [
            ["local", local === null ? "保留本机删除" : "保留本机"],
            ["remote", remote === null ? "采用远端删除" : "采用远端"],
            ...(editor ? [["edited", "保存合并结果"]] : []),
        ]) {
            const button = actions.createEl("button", {text: label, cls: option === "edited" ? "mod-cta" : ""});
            buttons.push(button);
            button.addEventListener("click", async () => {
                buttons.forEach(item => { item.disabled = true; });
                status.setText("正在检查并保存版本…");
                try {
                    await this.plugin.finishConflict(this.snapshot, option, editor?.value);
                    new Notice("已解决同步冲突");
                    this.close();
                } catch (error) {
                    status.dataset.state = "error";
                    status.setText(error.message);
                    buttons.forEach(item => { item.disabled = false; });
                }
            });
        }
    }

    showVersions(local, base, remote) {
        const group = this.contentEl.createDiv({cls: "simple-note-sync-versions"});
        for (const [kind, label, value] of [
            ["local", "本机", local], ["base", "共同旧版本", base], ["remote", "远端", remote],
        ]) {
            const panel = group.createDiv({cls: "simple-note-sync-version", attr: {"data-side": kind}});
            panel.createEl("strong", {text: label});
            panel.createEl("pre", {text: value ?? "此处没有可显示的文本"});
        }
    }
}

class ConflictPicker extends FuzzySuggestModal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
        this.setPlaceholder("查找待处理的同步冲突");
    }
    getItems() { return Object.keys(this.plugin.state.conflicts).sort(); }
    getItemText(path) { return path; }
    async onChooseItem(path) {
        try {
            const snapshot = await this.plugin.readConflict(path);
            new ConflictEditor(this.app, this.plugin, snapshot).open();
        } catch (error) {
            new Notice(error.message);
        }
    }
}

module.exports = {ConflictPicker};
