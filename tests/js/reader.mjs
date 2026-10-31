// Runs the hub page's reader (static/app.js) against a stub DOM: render() must not throw and
// must show the plain-language verdict and the preregistration table.
import { readFileSync } from "node:fs";

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ""; this.className = "";
    this.hidden = true; this.listeners = {}; this.classList = { add() {}, remove() {} }; }
  append(...c) { this.children.push(...c); }
  replaceChildren(...c) { this.children = c; }
  addEventListener(t, f) { this.listeners[t] = f; }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" "); }
}
const nodes = { drop: new Node_("div"), file: new Node_("input"), result: new Node_("div"),
  trust: Object.assign(new Node_("script"), { textContent: "{}" }) };
globalThis.document = { documentElement: { lang: process.argv[3] || "en" },
  getElementById: (id) => nodes[id], createElement: (t) => new Node_(t) };
const bundleText = readFileSync(process.argv[2], "utf8");
nodes.file.files = [{ name: "x.pvb", text: async () => bundleText }];
await import("../../src/provena/server/static/app.js");
await nodes.file.listeners.change();
console.log(JSON.stringify({ hidden: nodes.result.hidden, cls: nodes.result.className,
  text: nodes.result.text() }));
