const {diff3Merge} = require("node-diff3");
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_FILE = 32 * 1024 * 1024;
const CONFLICTS = "Sync conflicts";
const MERGE_LIMIT = 256 * 1024;

function encode64(bytes) {
    let raw = "";
    for (let offset = 0; offset < bytes.length; offset += 8192) {
        raw += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    }
    return btoa(raw);
}

function decode64(value) {
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function hex(bytes) {
    return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function digest(bytes) {
    return hex(await crypto.subtle.digest("SHA-256", bytes));
}

function validPath(path) {
    return typeof path === "string"
        && !/[\\\x00-\x1f]/.test(path)
        && path.split("/").every(part => part.length && !part.startsWith("."))
        && path.split("/")[0] !== CONFLICTS;
}

function inScope(path, scope) {
    if (!validPath(path)) return false;
    if (scope.kind === "vault") return true;
    if (scope.kind === "file") return path === scope.path;
    return path.startsWith(scope.path + "/");
}

async function cryptography(secret) {
    const raw = decode64(secret);
    if (raw.length !== 32) throw Error("仓库密钥无效");
    const root = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    function derive(label, algorithm, operations) {
        return crypto.subtle.deriveKey({
            name: "HKDF", hash: "SHA-256",
            salt: encoder.encode("simple-note-sync-v1"), info: encoder.encode(label),
        }, root, algorithm, false, operations);
    }
    const contentKey = await derive("content", {name: "AES-GCM", length: 256}, ["encrypt", "decrypt"]);
    const pathKey = await derive("paths", {name: "HMAC", hash: "SHA-256"}, ["sign"]);
    return {
        async pathId(path) {
            return hex(await crypto.subtle.sign("HMAC", pathKey, encoder.encode(path)));
        },
        async seal(bytes, context) {
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt({
                name: "AES-GCM", iv: nonce, additionalData: encoder.encode(context),
            }, contentKey, bytes);
            return encode64(nonce) + "." + encode64(new Uint8Array(ciphertext));
        },
        async open(value, context) {
            const [nonce, ciphertext] = value.split(".");
            return await crypto.subtle.decrypt({
                name: "AES-GCM", iv: decode64(nonce), additionalData: encoder.encode(context),
            }, contentKey, decode64(ciphertext));
        },
    };
}

async function readManifest(cipher, scope, request) {
    const remote = new Map();
    const pathQuery = scope.kind === "file" && validPath(scope.path)
        ? "?id=" + await cipher.pathId(scope.path) : "";
    for (const entry of await request("GET", "/v1/manifest" + pathQuery)) {
        const meta = JSON.parse(decoder.decode(await cipher.open(
            entry.metadata, entry.id + ":metadata:" + entry.revision)));
        if (!validPath(meta.path) || await cipher.pathId(meta.path) !== entry.id
            || !(meta.hash === null || /^[0-9a-f]{64}$/.test(meta.hash))) {
            throw Error("远端记录校验失败");
        }
        if (inScope(meta.path, scope)) remote.set(meta.path, {...entry, hash: meta.hash});
    }
    return remote;
}

async function revisionData(cipher, request, id, revision, hash, historical = false) {
    if (hash === null) return null;
    const suffix = historical ? "?revision=" + revision : "";
    const item = await request("GET", "/v1/files/" + id + suffix);
    if (item.revision !== revision) throw Error("同步期间远端有更新，请重试");
    const bytes = await cipher.open(item.data, id + ":data:" + revision);
    if (await digest(bytes) !== hash) throw Error("文件完整性校验失败");
    return bytes;
}

async function writeRevision(cipher, request, id, path, revision, bytes, hash) {
    if (bytes && bytes.byteLength > MAX_FILE) throw Error("文件超过 32 MiB：" + path);
    const metadata = await cipher.seal(
        encoder.encode(JSON.stringify({path, hash})), id + ":metadata:" + (revision + 1));
    const data = bytes === null ? null : await cipher.seal(bytes, id + ":data:" + (revision + 1));
    const result = await request("PUT", "/v1/files/" + id, {previous: revision, metadata, data});
    return {hash, revision: result.revision};
}

const hashOf = bytes => bytes === null ? null : digest(bytes);

function markdown(bytes) {
    if (bytes === null || bytes.byteLength > MERGE_LIMIT) return null;
    try {
        return new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes);
    } catch {
        return null;
    }
}

function mergeMarkdown(local, base, remote) {
    const versions = [local, base, remote].map(markdown);
    if (versions.includes(null)) return null;
    const lines = versions.map(value => value.match(/[^\n]*\n|[^\n]+$/g) ?? []);
    if (lines.some(value => value.length > 6000)) return null;
    return diff3Merge(...lines);
}

async function commonAncestor(cipher, request, id, prior) {
    if (!prior.revision || prior.hash === null) return null;
    try {
        return await revisionData(cipher, request, id, prior.revision, prior.hash, true);
    } catch (error) {
        if (error.status === 404) return null;
        throw error;
    }
}

async function inspectConflict({path, key, checkpoints, store, request}) {
    const scope = {kind: "file", path};
    if (!validPath(path)) throw Error("文件路径无效");
    const cipher = await cryptography(key);
    const record = (await readManifest(cipher, scope, request)).get(path);
    if (!record) throw Error("远端没有对应版本");
    const local = await store.read(path);
    const remote = await revisionData(cipher, request, record.id, record.revision, record.hash);
    const base = await commonAncestor(cipher, request, record.id, checkpoints[path] ?? {revision: 0, hash: null});
    return {path, local, remote, base, localHash: await hashOf(local), remoteHash: record.hash,
        revision: record.revision, id: record.id};
}

async function resolveConflict({snapshot, option, text, key, store, request, persist}) {
    const {path, id, revision, localHash, remoteHash} = snapshot;
    const conflictChanged = () => new Error("打开面板后版本已变化，请重新查看冲突。");
    if (!["local", "remote", "edited"].includes(option)) throw Error("无效的解决方式");
    const cipher = await cryptography(key);
    const record = (await readManifest(cipher, {kind: "file", path}, request)).get(path);
    if (!record || record.revision !== revision || record.hash !== remoteHash) throw conflictChanged();
    if (await hashOf(await store.read(path)) !== localHash) throw conflictChanged();
    const bytes = option === "local" ? snapshot.local
        : option === "remote" ? snapshot.remote : encoder.encode(text).buffer;
    const hash = await hashOf(bytes);
    const entry = hash === remoteHash ? {hash, revision}
        : await writeRevision(cipher, request, id, path, revision, bytes, hash);
    if (hash !== localHash) {
        if (await hashOf(await store.read(path)) !== localHash) throw conflictChanged();
        await store.write(path, bytes);
    }
    await persist(path, entry, id);
}

async function synchronize({scope, direction = "both", key, checkpoints, store, request, persist}) {
    if (!["pull", "both", "push"].includes(direction)) throw Error("同步方向无效");
    const cipher = await cryptography(key);
    const remote = await readManifest(cipher, scope, request);
    const paths = new Set([...remote.keys(), ...store.paths().filter(path => inScope(path, scope))]);
    const result = {uploaded: 0, downloaded: 0, conflicts: 0, merged: 0};
    for (const path of paths) {
        const record = remote.get(path);
        const prior = Object.hasOwn(checkpoints, path) ? checkpoints[path] : {hash: null, revision: 0};
        const current = await store.read(path);
        const localHash = await hashOf(current);
        const remoteHash = record?.hash ?? null;
        const revision = record?.revision ?? 0;
        if (revision < prior.revision) throw Error("服务器版本倒退，已暂停处理：" + path);
        const id = record?.id ?? await cipher.pathId(path);
        if (localHash === remoteHash) {
            await persist(path, {hash: localHash, revision}, id);
            continue;
        }
        const localChanged = localHash !== prior.hash;
        const remoteChanged = remoteHash !== prior.hash || revision !== prior.revision;
        if (localChanged && remoteChanged) {
            if (direction !== "push") {
                const other = await download();
                if (direction === "both" && /\.md$/i.test(path) && current && other) {
                    const base = await commonAncestor(cipher, request, id, prior);
                    const blocks = mergeMarkdown(current, base, other);
                    if (blocks && blocks.every(block => block.ok)
                        && await hashOf(await store.read(path)) === localHash) {
                        const bytes = encoder.encode(blocks.flatMap(block => block.ok).join("")).buffer;
                        const hash = await digest(bytes);
                        try {
                            const entry = hash === remoteHash ? {hash, revision}
                                : await writeRevision(cipher, request, id, path, revision, bytes, hash);
                            if (hash !== localHash) {
                                if (await hashOf(await store.read(path)) !== localHash) {
                                    throw Error("合并期间本机文件又被修改，已保留本机改动。");
                                }
                                await store.write(path, bytes);
                            }
                            await persist(path, entry, id);
                            result.merged++;
                        } catch (error) {
                            if (error.status !== 409) throw error;
                            await store.conflict(path, other, revision);
                            result.conflicts++;
                        }
                        continue;
                    }
                }
                await store.conflict(path, other, revision);
            }
            result.conflicts++;
            continue;
        }
        if (localChanged && direction !== "pull") {
            try {
                const entry = await writeRevision(cipher, request, id, path, revision, current, localHash);
                await persist(path, entry, id);
                result.uploaded++;
            } catch (error) {
                if (error.status !== 409) throw error;
                result.conflicts++;
            }
        } else if (remoteChanged && !localChanged && direction !== "push") {
            const other = await download();
            const latest = await store.read(path);
            if ((latest === null ? null : await digest(latest)) !== localHash) {
                await store.conflict(path, other, revision);
                result.conflicts++;
                continue;
            }
            await store.write(path, other);
            await persist(path, {hash: remoteHash, revision}, id);
            result.downloaded++;
        }

        async function download() {
            return revisionData(cipher, request, id, revision, remoteHash);
        }
    }
    return result;
}

module.exports = {CONFLICTS, encode64, decode64, inScope, validPath, markdown, mergeMarkdown,
    synchronize, inspectConflict, resolveConflict, cryptography};
