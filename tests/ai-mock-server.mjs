#!/usr/bin/env node
/**
 * Mock OpenAI-compatible provider for acceptance-v03 — runs as its OWN process
 * (the acceptance parent is blocked by spawnSync, so an in-process server would
 * deadlock the child's fetch). Serves canned claims and captures the last
 * request body to <captureFile> for redaction/protocol assertions.
 */
import { createServer } from "node:http";
import { writeFileSync } from "node:fs";

const capturePath = process.argv[2];

const CANNED = {
  choices: [{
    message: {
      content: JSON.stringify({
        findings: [
          { file: "app/api/admin/stats/route.ts", line: 5, rule_hint: "NEXT-005", severity: "medium", evidence_snippet: "export async function POST(req: NextRequest)", rationale: "cookie sessions exist elsewhere; this mutating endpoint has no CSRF signal" },
          { file: "lib/logline.ts", line: 99, rule_hint: "SAST-001", severity: "critical", evidence_snippet: "TOTALLY FABRICATED EVIDENCE TEXT THAT EXISTS NOWHERE", rationale: "hallucinated" },
          { file: "src/does/not/exist.ts", line: 1, rule_hint: "LOGS-001", severity: "high", evidence_snippet: "console.log('secret')", rationale: "file is not in the repo" },
          { file: "lib/logline.ts", line: 1, rule_hint: "MADEUP-999", severity: "high", evidence_snippet: "console.log(\"session for debugging:\"", rationale: "unknown rule id" },
        ],
      }),
    },
  }],
};

const server = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (capturePath) { try { writeFileSync(capturePath, body); } catch { /* best-effort */ } }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(CANNED));
  });
});

server.listen(0, "127.0.0.1", () => {
  process.stdout.write(JSON.stringify({ port: server.address().port }) + "\n");
});
