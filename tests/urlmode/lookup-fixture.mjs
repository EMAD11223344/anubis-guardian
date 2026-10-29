#!/usr/bin/env node
/**
 * Fixture servers for tests/urlmode/verify-lookup-contract.mjs.
 * Prints one JSON line on stdout when ready: { port, deadPort }.
 * - port:     live fixture (HTTP 200 "alive" page)
 * - deadPort: a port that was bound then released — connections to it now
 *             hit nothing and fail with ECONNREFUSED (true network failure)
 */
import { createServer } from "node:http";

const server = createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end("<!doctype html><html><head><title>fix-fixture</title></head><body><h1>alive</h1></body></html>");
});

// dead port: bind once to claim a free port, then immediately release it
const deadHolder = createServer();
await new Promise((r) => deadHolder.listen(0, "127.0.0.1", r));
const deadPort = deadHolder.address().port;
await new Promise((r) => deadHolder.close(r));

await new Promise((r) => server.listen(0, "127.0.0.1", r));
console.log(JSON.stringify({ port: server.address().port, deadPort }));
setInterval(() => {}, 60_000);
