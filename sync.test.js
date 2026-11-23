const assert = require("node:assert/strict");
const {spawn, execFileSync} = require("node:child_process");
const {mkdtemp, readdir, rmdir, unlink} = require("node:fs/promises");
const {tmpdir} = require("node:os");
const {join} = require("node:path");
const {createInterface} = require("node:readline");
const {once} = require("node:events");
const {test} = require("node:test");
const vm = require("node:vm");
const fs = require("node:fs");
const {encode64, synchronize, inspectConflict, resolveConflict} = require("./plugin/engine");

const python = process.platform === "win32" ? "python" : "python3";
const secret = () => encode64(crypto.getRandomValues(new Uint8Array(32)));
const file = value => new TextEncoder().encode(value).buffer;
const contents = value => new TextDecoder().decode(value);

function device(key, request, initial = {}) {
    const files = new Map(Object.entries(initial).map(([path, value]) => [path, file(value)]));
    const checkpoints = Object.create(null);
    const conflicts = new Map();
    const store = {
        paths: () => [...files.keys()],
        read: async path => files.get(path) ?? null,
        write: async (path, data) => data === null ? files.delete(path) : files.set(path, data),
        conflict: async (path, data) => conflicts.set(path, data),
    };
    const persist = async (path, checkpoint) => { checkpoints[path] = checkpoint; };
    const session = {key, request, store, checkpoints, persist};
    return {
        files, conflicts,
        sync: (scope, direction) => synchronize({scope, direction, ...session}),
        inspect: path => inspectConflict({path, ...session}),
        resolve: (snapshot, option, text) => resolveConflict({snapshot, option, text, ...session}),
    };
}

test("real server isolates users and vaults, supports scopes and preserves divergent edits", async t => {
    const dir = await mkdtemp(join(tmpdir(), "simple-note-sync-"));
    const server = spawn(python, ["-u", "-c", `
import sys
from http.server import ThreadingHTTPServer
from server import init, grant, handler, database
import accounts
path = sys.argv[1]
init(path)
with database(path) as db:
    accounts.set_invite(db, "local-invite-only")
owner = grant(path, "owner", "primary")
friend = grant(path, "friend", "private")
shared = grant(path, "friend", "primary")
with ThreadingHTTPServer(("127.0.0.1", 0), handler(path)) as server:
    print(server.server_port, owner, friend, shared)
    server.serve_forever()
`, join(dir, "pilot.sqlite3")], {stdio: ["ignore", "pipe", "inherit"]});
    t.after(async () => {
        if (server.exitCode === null) {
            const stopped = once(server, "exit");
            server.kill();
            await stopped;
        }
        for (const name of await readdir(dir)) await unlink(join(dir, name));
        await rmdir(dir);
    });
    const lines = createInterface({input: server.stdout});
    const [port, owner, friend, shared] = (await once(lines, "line"))[0].split(" ");
    const requester = token => async (method, path, body) => {
        const response = await fetch(`http://127.0.0.1:${port}${path}`, {
            method, headers: {Authorization: "Bearer " + token},
            body: body === undefined ? undefined : JSON.stringify(body),
            signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) throw Object.assign(Error("HTTP " + response.status), {status: response.status});
        return response.json();
    };
    const localAccount = {exports: {}};
    vm.runInNewContext(fs.readFileSync(join(__dirname, "plugin/account.js"), "utf8"), {
        module: localAccount, crypto, TextEncoder,
        require: name => name === "obsidian" ? {
            requestUrl: async options => {
                const response = await fetch(`http://127.0.0.1:${port}/v1/account/connect`, {
                    method: options.method, body: options.body, signal: AbortSignal.timeout(5000),
                });
                return {status: response.status, json: await response.json()};
            },
        } : require("./plugin/engine"),
    });
    const {connectAccount} = localAccount.exports;
    const account = {account: "pilot-owner", vault: "main", password: "local-test-password", invite: "local-invite-only"};
    await assert.rejects(connectAccount({...account, mode: "register", invite: "wrong"}), /口令错误/);
    const first = await connectAccount({...account, mode: "register"});
    const second = await connectAccount({...account, mode: "login", invite: ""});
    assert.equal(first.key, second.key);
    assert.notEqual(first.token, second.token);
    await assert.rejects(connectAccount({...account, mode: "login", password: "wrong-password"}), /密码错误/);
    const otherVault = await connectAccount({...account, vault: "second", mode: "create"});
    assert.notEqual(first.key, otherVault.key);
    const otherAccount = await connectAccount({...account, account: "pilot-friend", mode: "register"});
    const pluginCipher = await require("./plugin/engine").cryptography(first.key);
    const context = "blueee-notes-plugin-list-v1";
    const payload = JSON.stringify([{id: "obsidian-excalidraw-plugin", name: "Excalidraw", version: "2.0.0", enabled: true}]);
    const encrypted = await pluginCipher.seal(file(payload), context);
    await requester(first.token)("POST", "/v1/plugin-list", {encrypted});
    const received = await requester(second.token)("GET", "/v1/plugin-list");
    assert.equal(contents(await pluginCipher.open(received.encrypted, context)), payload);
    assert.deepEqual(await requester(otherVault.token)("GET", "/v1/plugin-list"), {encrypted: null});
    assert.deepEqual(await requester(otherAccount.token)("GET", "/v1/plugin-list"), {encrypted: null});
    execFileSync(python, ["server.py", "--db", join(dir, "pilot.sqlite3"), "disable-account", account.account]);
    await assert.rejects(requester(first.token)("GET", "/v1/manifest"), /401/);
    await assert.rejects(requester(second.token)("GET", "/v1/plugin-list"), /401/);
    assert.deepEqual(await requester(otherAccount.token)("GET", "/v1/manifest"), []);
    const ownerRequest = requester(owner);
    const key = secret();
    const a = device(key, ownerRequest, {"随手记.md": "hello", "工作/A.md": "office", "工作/sub/B.png": "image", "其他/X.md": "outside"});
    const b = device(key, requester(shared));
    const single = {kind: "file", path: "随手记.md"};
    const folder = {kind: "folder", path: "工作"};
    const whole = {kind: "vault"};
    assert.equal((await a.sync(single)).uploaded, 1);
    assert.equal((await b.sync(single)).downloaded, 1);
    assert.deepEqual([...b.files.keys()], ["随手记.md"]);
    assert.deepEqual(await requester(friend)("GET", "/v1/manifest"), []);
    await assert.rejects(requester("invalid")("GET", "/v1/manifest"), /401/);
    const [entry] = await ownerRequest("GET", "/v1/manifest");
    await assert.rejects(requester(friend)("GET", "/v1/files/" + entry.id), /404/);
    await assert.rejects(ownerRequest("PUT", "/v1/files/" + entry.id, {previous: 0, metadata: "stale", data: null}), /409/);
    assert.equal((await a.sync(folder)).uploaded, 2);
    assert.equal((await b.sync(folder)).downloaded, 2);
    assert.equal(b.files.has("其他/X.md"), false);
    assert.equal((await a.sync(whole)).uploaded, 1);
    assert.equal((await b.sync(whole)).downloaded, 1);
    a.files.set("随手记.md", file("local edit"));
    b.files.set("随手记.md", file("remote edit"));
    assert.equal((await b.sync(single)).uploaded, 1);
    assert.equal((await a.sync(single)).conflicts, 1);
    assert.equal(contents(a.files.get("随手记.md")), "local edit");
    assert.equal(contents(a.conflicts.get("随手记.md")), "remote edit");
    b.files.delete("工作/A.md");
    assert.equal((await b.sync(folder)).uploaded, 1);
    assert.equal((await a.sync(folder)).downloaded, 1);
    assert.equal(a.files.has("工作/A.md"), false);
    assert.equal(a.files.has("其他/X.md"), true);
    assert.doesNotMatch(JSON.stringify(await ownerRequest("GET", "/v1/manifest")), /随手记|remote edit|工作/);
    let interrupt = true;
    const c = device(key, async (method, path, body) => {
        const response = await ownerRequest(method, path, body);
        if (method === "PUT" && interrupt) {
            interrupt = false;
            throw Error("connection closed after commit");
        }
        return response;
    }, {"重试.md": "try again"});
    const retryScope = {kind: "file", path: "重试.md"};
    await assert.rejects(c.sync(retryScope), /connection closed/);
    assert.equal((await c.sync(retryScope)).uploaded, 0);
    assert.equal((await b.sync(retryScope)).downloaded, 1);
    assert.equal(contents(b.files.get("重试.md")), "try again");

    const pushOnly = {kind: "file", path: "推送.md"};
    const pullOnly = {kind: "file", path: "拉取.md"};
    a.files.set("推送.md", file("new on a"));
    b.files.set("拉取.md", file("new on b"));
    assert.equal((await b.sync(pullOnly, "push")).uploaded, 1);
    const fetchedOnA = [];
    const d = device(key, async (method, route, body) => {
        fetchedOnA.push([method, route]);
        return ownerRequest(method, route, body);
    }, {"推送.md": "new on a"});
    const outgoing = await d.sync(whole, "push");
    assert.equal(outgoing.uploaded, 1);
    assert.equal(outgoing.downloaded, 0);
    assert(!fetchedOnA.some(([method, route]) => method === "GET" && route.startsWith("/v1/files/")));
    assert.equal((await a.sync(pushOnly, "pull")).uploaded, 0);
    assert.equal((await a.sync(pullOnly, "pull")).downloaded, 1);
    assert.equal((await b.sync(pushOnly, "pull")).downloaded, 1);
    d.files.set("推送.md", file("local changed"));
    b.files.set("推送.md", file("remote changed"));
    assert.equal((await b.sync(pushOnly, "push")).uploaded, 1);
    fetchedOnA.length = 0;
    assert.equal((await d.sync(pushOnly, "push")).conflicts, 1);
    assert.equal(fetchedOnA.length, 1);
    assert.equal(fetchedOnA[0][0], "GET");
    assert.match(fetchedOnA[0][1], /^\/v1\/manifest\?id=/);
    assert.equal(contents(d.files.get("推送.md")), "local changed");

    const mergePath = "合并.md";
    const mergeScope = {kind: "file", path: mergePath};
    a.files.set(mergePath, file("标题\n保留\n结尾\n"));
    await a.sync(mergeScope);
    await b.sync(mergeScope);
    a.files.set(mergePath, file("新标题\n保留\n结尾\n"));
    b.files.set(mergePath, file("标题\n保留\n新结尾\n"));
    await b.sync(mergeScope);
    assert.equal((await a.sync(mergeScope)).merged, 1);
    assert.equal(contents(a.files.get(mergePath)), "新标题\n保留\n新结尾\n");
    await b.sync(mergeScope);
    a.files.set(mergePath, file("我的标题\n保留\n新结尾\n"));
    b.files.set(mergePath, file("远端标题\n保留\n新结尾\n"));
    await b.sync(mergeScope);
    assert.equal((await a.sync(mergeScope)).conflicts, 1);
    const snapshot = await a.inspect(mergePath);
    assert.equal(contents(snapshot.base), "新标题\n保留\n新结尾\n");
    a.files.set(mergePath, file("保存前又改了这篇"));
    await assert.rejects(a.resolve(snapshot, "remote"), /版本已变化/);
    const fresh = await a.inspect(mergePath);
    await a.resolve(fresh, "edited", "手动合并结果\n");
    await b.sync(mergeScope);
    assert.equal(contents(b.files.get(mergePath)), "手动合并结果\n");

    const firstDevice = crypto.randomUUID();
    const secondDevice = crypto.randomUUID();
    const latest = (await ownerRequest("GET", "/v1/files/" + fresh.id)).revision;
    await ownerRequest("POST", "/v1/ack", {id: fresh.id, device: firstDevice, revision: latest});
    await ownerRequest("POST", "/v1/ack", {id: fresh.id, device: secondDevice, revision: 1});
    execFileSync(python, ["-c", `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("UPDATE history SET superseded=1")
`, join(dir, "pilot.sqlite3")]);
    await ownerRequest("POST", "/v1/ack", {id: fresh.id, device: firstDevice, revision: latest});
    assert.equal((await ownerRequest("GET", "/v1/files/" + fresh.id + "?revision=1")).revision, 1);
    await ownerRequest("POST", "/v1/ack", {id: fresh.id, device: secondDevice, revision: latest});
    await assert.rejects(ownerRequest("GET", "/v1/files/" + fresh.id + "?revision=1"), /404/);
    assert.equal((await ownerRequest("GET", "/v1/files/" + fresh.id)).revision, latest);
});

test("automatic sync waits for saved active notes and respects focus and conflicts", async () => {
    const obsidian = Object.fromEntries(
        ["Plugin", "PluginSettingTab", "Modal", "FuzzySuggestModal", "TFile"].map(name => [name, class {}]));
    const sandbox = {
        module: {exports: {}},
        require: name => name === "obsidian" ? obsidian
            : name === "./engine" ? require("./plugin/engine") : {ConflictPicker: class {}},
        window: {setTimeout, clearTimeout},
        document: {hidden: false},
        navigator: {onLine: true},
    };
    vm.runInNewContext(fs.readFileSync(require.resolve("./plugin/main"), "utf8"), sandbox);
    const instance = new sandbox.module.exports();
    instance.state = {auto: true, pair: {}, conflicts: {"冲突.md": 2}};
    instance.pending = new Set();
    const log = [];
    instance.sync = async (scope, options) => {
        log.push([scope.path, options.automatic]);
        return {state: "success", message: ""};
    };
    const note = Object.assign(new obsidian.TFile(), {path: "当前.md", extension: "md"});
    instance.queueAuto(note);
    assert(instance.autoTimer);
    clearTimeout(instance.autoTimer);
    instance.autoTimer = undefined;
    sandbox.document.hidden = true;
    await instance.flushAuto();
    assert.equal(log.length, 0);
    sandbox.document.hidden = false;
    instance.pending.add("冲突.md");
    await instance.flushAuto();
    assert.deepEqual(log, [["当前.md", true]]);
    instance.state.auto = false;
    instance.queueAuto(note);
    assert.equal(instance.pending.size, 0);
});

test("the sync dialog opens with Obsidian's modal keymap scope", () => {
    class Element {
        constructor() { this.dataset = {}; }
        createDiv() { return new Element(); }
        createEl() { return new Element(); }
        createSpan() { return new Element(); }
        addClass() {}
        toggleClass() {}
        setText() {}
        addEventListener() {}
    }
    class Modal {
        constructor(app) {
            this.app = app;
            this.scope = {};
            this.contentEl = new Element();
            this.modalEl = new Element();
        }
        setTitle() {}
    }
    class Setting {
        setName() { return this; }
        setDesc() { return this; }
        addToggle() { return this; }
    }
    const sandbox = {
        module: {exports: {}},
        require: name => name === "obsidian"
            ? {Modal, Setting, Plugin: class {}, PluginSettingTab: class {}, FuzzySuggestModal: class {}, setIcon() {}}
            : name === "./engine" ? require("./plugin/engine") : {ConflictPicker: class {}},
    };
    const source = fs.readFileSync(require.resolve("./plugin/main"), "utf8");
    const Picker = vm.runInNewContext(source + "\nScopePicker;", sandbox);
    const picker = new Picker({
        workspace: {getActiveFile: () => ({path: "验收.md"})},
        vault: {getName: () => "测试仓"},
    }, {state: {pair: {}, auto: false, conflicts: {}}});
    picker.onOpen();
    assert.equal(picker.primary.disabled, false);
    assert.equal(picker.selectedScope().path, "验收.md");
});
