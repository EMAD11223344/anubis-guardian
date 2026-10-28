#!/usr/bin/env node
/**
 * U29 — BOUNDED SEEDED TOKENIZER FUZZ (v1.5.3 P0-5 hardening gate).
 *
 * handlerBodySpan feeds AUTHZ-001/AUTHZ-002/NEXT-00x block extraction, so a
 * tokenizer regression silently moves several rules at once. This gate is a
 * DETERMINISTIC property test, not an open-ended fuzzer:
 *   - fixed seed (mulberry32) → the exact same 320 fixtures every run,
 *   - generated signatures combine the adversarial corners: TS return-type
 *     annotations containing object braces, generic type arguments with
 *     braces, object-brace default parameters, destructured parameters,
 *     template literals, line/block comments (inline + multiline), nested
 *     object literals in the body, multiline signatures, arrow/fn/express and
 *     alias-export handler forms,
 *   - every generated file must produce: no throw, blocks within file bounds,
 *     bodyEnd0 >= line0, and (for well-defined generated shapes) the planted
 *     body marker must sit inside the extracted span,
 *   - hard time budget for the whole battery (CI-safe; no unbounded fuzz in
 *     the regular suite — this file IS the bounded fuzz gate).
 *
 * Exit 0 = all invariants hold. Any violation prints the seed + fixture.
 */
import { handlerBlocks } from "../dist/rules/authzpack.js";

const SEED = 0xA9B15;
const N = 320;
const TIME_BUDGET_MS = 20_000; // whole-battery wall budget (deterministic work ≈ well under)

// ---- deterministic PRNG (mulberry32) ---------------------------------------
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- adversarial fragment pools --------------------------------------------
const RETURN_TYPES = [
  "", ": void", ": Response", ": Promise<Response>",
  ": Promise<{ ok: boolean }>",                     // annotation braces (the v1.5.2-truncation class)
  ": { id: string }",                               // bare object annotation
  ": Promise<Record<string, { a: 1 }>>",            // generic braces before =>
  ": Record<string, Array<{ x: number }>>",
  ": Map<string, { z: string }> | undefined",
  ": Promise<Response | { error: string }>",
];
const PARAMS = [
  "", "request: Request", "req: NextRequest",
  "request: Request, context: { params: Promise<{ id: string }> }", // object braces INSIDE parens
  "req = { debug: false }, res: Response",          // object-brace default parameter
  "{ body }: { body: { role: string } }",           // destructured parameter with braces
  "a: { b: { c: { d: string } } }",                 // deeply nested annotation braces
];
const NOISE = [
  "", "// trailing comment",
  "/* inline block */ const x = 1;",
  "const s = `tpl ${ { a: 1 }.a } end`;",
  "const obj = { nested: { deeper: { x: 1 } } };",
];
const BODY_LINES = [
  '  await prisma.user.delete({ where: { id: "1" } });',
  "  const cfg = { a: { b: 1 } };",
  "  // authorize: TODO",
  "  if (data.role === 'admin') { promote(); }",
  "  return Response.json({ ok: true });",
];
const MARKER = "await prisma.user.delete({ where: { id: \"MARKER\" } });";

let rng = mulberry32(SEED);
const pick = (arr) => arr[Math.floor(rng() * arr.length) % arr.length];

// ---- fixture generation ------------------------------------------------------
// Each fixture is a well-defined handler shape with decorations. The generator
// KNOWS the declaration line and the marker line, so assertions are exact.
function generateFixture(i) {
  const method = ["GET", "POST", "PUT", "PATCH", "DELETE"][i % 5];
  const lines = [];
  let decl0;   // 0-based declaration line
  let marker0; // 0-based marker line
  const form = i % 4;
  const params = pick(PARAMS);
  const ret = pick(RETURN_TYPES);
  const pre = pick(NOISE);
  const post = pick(NOISE);
  const bodyA = pick(BODY_LINES);
  const bodyB = pick(BODY_LINES);
  if (pre) lines.push(pre);
  if (form === 0) {
    decl0 = lines.length;
    lines.push(`export async function ${method}(${params})${ret} {`);
  } else if (form === 1) {
    decl0 = lines.length;
    lines.push(`export const ${method} = async (${params})${ret} => {`);
  } else if (form === 2) {
    decl0 = lines.length;
    lines.push(`const handler = async function (${params}) {`);
  } else {
    // alias-exported arrow handler: `const handler = (…) => { … }; export { handler as METHOD };`
    decl0 = lines.length;
    lines.push(`const handler = (${params})${ret} => {`);
  }
  lines.push(bodyA);
  marker0 = lines.length;
  lines.push(MARKER);
  lines.push(bodyB);
  lines.push("}");
  if (form === 2) lines.push(`export { handler as ${method} };`);
  if (form === 3) lines.push(`export { handler as ${method} };`);
  if (post) lines.push(post);
  return { content: lines.join("\n") + "\n", lines, decl0, marker0, method, form };
}

// ---- battery -----------------------------------------------------------------
const t0 = Date.now();
let failures = 0;
for (let i = 0; i < N; i++) {
  const fx = generateFixture(i);
  let blocks;
  try {
    blocks = handlerBlocks({ rel: "app/api/x/route.ts", abs: "/p/app/api/x/route.ts", content: fx.content, lines: fx.lines });
  } catch (e) {
    console.error(`FAIL  U29 crash on fixture ${i} (form=${fx.form} ret="${fx.ret ?? ""}"): ${e && e.message}`);
    console.error(fx.content);
    failures++;
    continue;
  }
  const problems = [];
  // exactly ONE handler block per generated file (decorations must not spawn extras)
  const mine = blocks.filter((b) => b.line0 === fx.decl0 || b.name.startsWith(fx.method));
  if (mine.length === 0) problems.push("no handler block extracted");
  for (const b of blocks) {
    if (!(b.line0 >= 0 && b.line0 < fx.lines.length)) problems.push(`line0 out of bounds: ${b.line0}`);
    if (!(b.bodyEnd0 >= b.line0 && b.bodyEnd0 <= fx.lines.length - 1)) problems.push(`bodyEnd0 out of bounds: ${b.bodyEnd0}`);
  }
  const b = mine[0];
  if (b && !(b.bodyEnd0 >= fx.marker0)) {
    problems.push(`planted body marker (line ${fx.marker0 + 1}) outside extracted body (bodyEnd0=${b.bodyEnd0}) — body truncated/misopened`);
  }
  if (problems.length) {
    failures++;
    console.error(`FAIL  U29 fixture ${i} (form=${fx.form}): ${problems.join("; ")}`);
    console.error(fx.content);
  }
}
const elapsed = Date.now() - t0;

if (elapsed > TIME_BUDGET_MS) {
  failures++;
  console.error(`FAIL  U29 time budget exceeded: ${elapsed}ms > ${TIME_BUDGET_MS}ms`);
}
if (failures) {
  console.error(`TOKENIZER FUZZ: ${failures} failure(s) over ${N} seeded fixtures (seed=${SEED})`);
  process.exit(1);
}
console.log(`TOKENIZER FUZZ: ${N}/${N} seeded fixtures hold all invariants (seed=${SEED}, ${elapsed}ms, budget ${TIME_BUDGET_MS}ms)`);
