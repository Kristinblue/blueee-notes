const fs = require("node:fs");
const esbuild = require("esbuild");

const licenses = ["LICENSE", "LICENSE-node-diff3.md"].map(file => fs.readFileSync(file, "utf8"));
esbuild.buildSync({
    entryPoints: ["plugin/main.js"],
    bundle: true,
    format: "cjs",
    target: "es2022",
    external: ["obsidian"],
    outfile: "dist/main.js",
    banner: {js: "/*!\n" + licenses.join("\n").replaceAll("*/", "* /") + "\n*/"},
});

for (const file of ["manifest.json", "plugin/styles.css"]) {
    fs.copyFileSync(file, "dist/" + file.split("/").pop());
}
