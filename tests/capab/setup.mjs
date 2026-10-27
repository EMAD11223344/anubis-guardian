#!/usr/bin/env node
/**
 * Capability acceptance harness (v1.4) — a synthetic tree containing POSITIVE
 * fixtures for each capability pack (A–F) plus CLEAN counterparts, scanned by
 * the REAL CLI; tests/verify-capab.mjs asserts the exact expected rules per
 * file. Generalization fixtures use shapes/var-names NOT used during rule
 * development (arrow handlers, router variants, different identifiers).
 */
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "app");
rmSync(app, { recursive: true, force: true });
const mk = (rel, body) => {
  const p = join(app, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, body);
};

// ---------- §A positives ----------
mk("app/api/tenants/del/route.ts", `import { prisma } from "@/db";
export async function POST(req: Request) {
  const data = await req.json();
  await prisma.user.update({ where: { id: data.id }, data: { role: data.role } });
  return NextResponse.json({ ok: true });
}
`);
// ---------- §A clean (authz call present) ----------
mk("app/api/tenants/safe/route.ts", `import { getSession } from "@/auth";
import { prisma } from "@/db";
export async function POST(req: Request) {
  const s = await getSession();
  await prisma.user.update({ where: { id: s.userId }, data: { theme: "dark" } });
  return NextResponse.json({ ok: true });
}
`);

// ---------- §A AUTHZ-002 positive (express/generalized) ----------
mk("server/perm-router.js", `const router = require("express").Router();
router.post("/promote", (req, res) => {
  if (req.body.isAdmin) { grant(req); }
  res.json({ ok: true });
});
`);

// ---------- §B positive: tenant schema + unscoped ops ----------
mk("prisma/schema.prisma", `model Invoice {
  id             Int    @id @default(autoincrement())
  organizationId Int
  amount         Int
}
`);
mk("app/api/invoice/route.ts", `import { prisma } from "@/db";
export async function DELETE(req: Request) {
  await prisma.invoice.delete({ where: { id: req.params.id } });
  return NextResponse.json({ ok: true });
}
`);
// ---------- §B clean: tenant-scoped ----------
mk("app/api/invoice-scoped/route.ts", `import { prisma } from "@/db";
export async function DELETE(req: Request) {
  await prisma.invoice.delete({ where: { id: req.params.id, organizationId: session.orgId } });
  return NextResponse.json({ ok: true });
}
`);

// ---------- §C positive ----------
mk("app/api/profile/route.ts", `export async function GET() {
  const u = await db.users.findFirst();
  return NextResponse.json({ name: u.name, password: u.passwordHash });
}
`);
// ---------- §C clean: stripped field ----------
mk("app/api/profile-clean/route.ts", `export async function GET() {
  const u = await db.users.findFirst();
  return NextResponse.json({ name: u.name, password: undefined });
}
`);

// ---------- §D positives ----------
mk("app/api/search/route.ts", `export const GET = async (req) => {
  const rgx = new RegExp(req.searchParams.get("q"));
  return find(rgx);
};
`);
mk("app/api/all-users/route.ts", `export async function GET() {
  const rows = await prisma.user.findMany();
  return NextResponse.json(rows);
}
`);
// ---------- §D clean ----------
mk("app/api/all-users-clean/route.ts", `export async function GET() {
  const rows = await prisma.user.findMany({ take: 25 });
  return NextResponse.json(rows);
}
`);
mk("app/api/search-clean/route.ts", `const PATTERN = /^[A-Za-z0-9]{3,32}$/;
export const GET = async (req) => {
  return find(PATTERN);
};
`);

// ---------- §F positives ----------
mk("server/uploader.ts", `import multer from "multer";
const upload = multer({ dest: ".uploads-tmp" });
app.post("/f", upload.single("file"), (req, res) => {
  fs.writeFile(path.join("public/assets", req.file.originalname), req.file.buffer);
  res.json({ saved: true });
});
`);
mk("server/extractor.js", `import AdmZip from "adm-zip";
import { createReadStream } from "fs";
export function extract(buf: Buffer, out: string) {
  const z = new AdmZip(buf);
  z.extractAllTo(out);
}
app.post("/import", (req, res) => {
  createReadStream(req.body.path).pipe(require("tar").x({ cwd: "/var/www/ex" }));
});
`);
// ---------- §F clean (limits + guards) ----------
mk("server/uploader-clean.ts", `import multer from "multer";
const upload = multer({ limits: { fileSize: 5 * 1024 * 1024, files: 3 } });
app.post("/f", upload.single("file"), (req, res) => {
  fs.writeFile(path.join(".private-store", generateServerSideName()), req.file.buffer);
  res.json({ saved: true });
});
`);
mk("server/extractor-clean.js", `import AdmZip from "adm-zip";
export function extract(buf: Buffer, out: string) {
  const z = new AdmZip(buf);
  z.getEntries()
    .filter((e) => !e.entryName.includes("..") && e.header.size < MAX_ENTRY && count < MAX_ENTRIES)
    .forEach((e) => z.extractEntryTo(e, join(out, path.basename(e.entryName))));
}
`);

console.log("capability acceptance fixture tree ready:", app);
