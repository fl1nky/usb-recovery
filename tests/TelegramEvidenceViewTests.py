"""Execute the dashboard's actual Telegram renderer without a browser or HTTP.sys."""
import json
from pathlib import Path
import subprocess


def main():
    source = (Path(__file__).resolve().parents[1] / "src/Recovery/Infrastructure/LocalWebServer.cs").read_text(encoding="utf-8-sig")
    start = source.index("async function loadTelegram() {")
    end = source.index("// Initial boot", start)
    javascript = source[start:end].replace('""', '"')
    harness = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
const renderer = RENDERER;
const payload = '<img src="https://example.invalid/track" onerror="globalThis.pwned=true">';
class Element {
  constructor() { this.children = []; this.value = ''; }
  set textContent(value) { this.value = String(value); this.children = []; }
  get textContent() { return this.value; }
  set innerHTML(value) {
    assert(!value.includes('example.invalid'), 'Evidence was assigned to innerHTML');
    this.value = value; this.children = [];
  }
  appendChild(child) { this.children.push(child); }
}
async function run(report) {
  const nodes = {};
  const document = {
    getElementById(id) { return nodes[id] || (nodes[id] = new Element()); },
    createElement() { return new Element(); }
  };
  const context = { document, fetch: async () => ({json: async () => report}) };
  vm.runInNewContext(renderer, context);
  await context.loadTelegram();
  assert(!context.pwned);
  return nodes;
}
(async () => {
  const report = {
    totalProfiles: 0, totalMessages: 1, activeMessages: 0, carvedMessages: 1,
    totalTextFragments: 1, tdfContainers: 0,
    messages: [{timestamp: payload, isCarved: true, peerType: payload, peerId: 17, text: payload, sourceOrigin: payload}],
    textFragments: [{Text: payload, SourcePath: payload, SourceOrigin: 'Freeblock', PageNumber: 2, Offset: 4500, ColumnIndex: 3}]
  };
  let nodes = await run(report);
  const rows = nodes['tg-tbody'].children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].children[4].textContent, payload);
  assert.equal(rows[1].children[4].textContent, payload);
  assert.equal(rows[1].children[0].textContent, 'Unknown');
  assert.equal(rows[1].children[2].textContent, 'Unknown');
  assert.equal(rows[1].children[3].textContent, 'Unknown');
  assert(rows[1].children[5].textContent.includes('4500, column 3'));
  assert(rows[0].children[1].textContent.includes('deletion unconfirmed'));
  assert(nodes['tg-stats'].textContent.includes('Unattributed') || nodes['tg-stats'].textContent.includes('unattributed'));
  assert(nodes['tg-stats'].textContent.includes('at most 300'));
  nodes = await run({totalProfiles:0, totalMessages:0, activeMessages:0, totalTextFragments:0, tdfContainers:0, messages:[], textFragments:[]});
  assert.equal(nodes['tg-tbody'].children.length, 1);
  assert.equal(nodes['tg-tbody'].children[0].children[1].textContent, 'No results in available sources');
  nodes = await run({error: payload});
  assert.equal(nodes['tg-tbody'].textContent, 'Error: ' + payload);
  console.log('PASS TelegramEvidenceViewTests: literal hostile content, unknown fields, provenance, bounded view, empty state; simulated DOM, no browser');
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(["node", "-e", harness.replace("RENDERER", json.dumps(javascript))], timeout=30)
    if completed.returncode:
        raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
