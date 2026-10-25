# دليل اختبار المالك — Anubis Guardian v1.0.0 | Owner Testing Guide

> الهدف: تشغّل اختبارين — **(A) اختبار الأداة نفسها** و**(B) دمجها في Business-OS** — وتسجل النتائج في نموذج الجزء الثالث وترسله لي. كل أمر هنا مكتوب مع **نتيجته المتوقعة بالظبط**؛ أي اختلاف = رجّعلي الـ output وخلاص.
>
> Purpose: run two tests — **(A) the tool itself**, **(B) Business-OS integration** — record results in the Part-C template and send it back. Every command below has its **exact expected result**; any mismatch = just send me the output.

---

## الجزء الأول — اختبار الأداة نفسها | Part A — Tool Self-Test

### A0 — التحضير | Setup (~5 دقائق)

```bash
unzip anubis-guardian-v1.0.zip -d anubis-guardian
cd anubis-guardian
npm install     # 4 حزم فقط — بعد كده الأداة أوفلاين بالكامل
npm test        # سلسلة التحقق الكاملة
```

**المتوقع من `npm test`** (≈ 2–4 دقائق، exit code = 0):

| المرحلة | المتوقع |
|---|---|
| build (tsc) | يخلص بدون أخطاء |
| honeypot | **49/49 بذرة** — score **0/F** (مزروع عمدًا: 10 critical + 54 high + 31 medium + 2 low) |
| clean corpus | **0 FP — score 100/A** |
| SARIF | PASS — Security-tab ready |
| acceptance v0.2 | ALL PASS |
| acceptance v0.3 | ALL GATES GREEN |
| mode2 verify | **33/33** |
| acceptance v0.4 | **47/47** |
| acceptance v1.0 | **45/45** |

> ⛔ لو أي سطر مختلف أو الـ exit ≠ 0 — **قف** وابعتلي آخر 30 سطر من الـ output.

### A1 — Mode 1: فحص مشروع حقيقي | Scan a real project

```bash
# 1) التقرير التفاعلي الأساسي
node dist/cli.js scan /path/to/your-project
```

**المتوقع:** تقرير في الطرفية — score من 100 + درجة A–F + findings مرتبة بالخطورة + قسم "Classes not covered" (الصدق في إيه اللي مش بيتفحص) + `Code map:` على كل finding. **Exit 0** في الوضع الافتراضي (بوابة الفشل تعمل بس مع `--fail-on`).

```bash
# 2) اختبار الحتمية — نفس الأمر مرتين لازم يطلع نفس الملف بايت-ببايت
node dist/cli.js scan /path/to/project --format json --output r1.json
node dist/cli.js scan /path/to/project --format json --output r2.json
diff r1.json r2.json && echo "DETERMINISTIC ✓"
```

**المتوقع:** `DETERMINISTIC ✓` (نفس الكود + نفس إصدار الأداة = نفس النتيجة حرفيًا).

```bash
# 3) كل الصيغ + برومبت الإصلاح
node dist/cli.js scan /path/to/project --format all --output out/report
node dist/cli.js scan /path/to/project --fix-prompt fix.md
```

**المتوقع:** ملفات `report.json/.sarif/.md/.html/.compact` + `fix.md` فيه برومبت جاهز تلصقه في الـ agent لإصلاح كل finding.

```bash
# 4) بوابة الـ CI — لازم تفشل على مشروع فيه critical وتنجح على نظيف
node dist/cli.js scan /path/to/project --fail-on critical --format json
echo "exit code = $?"
```

**المتوقع:** مشروع فيه CRITICAL → `exit code = 1` + رسالة `gate: --fail-on critical — failing`. مشروع نظيف → `0`.

```bash
# 5) اختياري — طبقة AI Review (تحتاج مفتاح: export ANUBIS_AI_API_KEY=...)
node dist/cli.js scan /path/to/project --ai-review
```

**المتوقع:** نفس التقرير + قسم `ai_review` (نتائج AI مسقوفة HIGH + `needs_confirmation: true` + `verified` من الـ verifier المستقل). **بدون مفتاح → exit 2 برسالة واضحة** (ده التصميم).

```bash
# 6) أدوات v0.3/v1.0 المساندة
node dist/cli.js test-authz /path/to/project              # مصفوفة الصلاحيات + اختبارات quarantine
node dist/cli.js init-hook                                # guard hook يمنع كتابة أسرار وقت التطوير
node dist/cli.js init-ci                                  # workflow بأقل صلاحيات + SARIF للـ Security tab
```

**المتوقع:** `test-authz` يولّد `authz-matrix.md/json` + مجلد اختبارات quarantine **بدون تنفيذها** (إنت اللي بتشغلها) · `init-hook` يكتب الـ hook في `.claude/settings.json` محليًا · `init-ci` يكتب `.github/workflows/anubis-guardian.yml` بـ SHA pins حقيقية.

### A2 — Mode 2: فحص موقعك المنشور | Scan your deployed site

```bash
# 1) L1 passive — مجاني، بدون أي إثبات ملكية، يعادل تصفح المتصفح بالظبط
node dist/cli.js scan-url https://your-site.com
```

**المتوقع:** تقرير فيه فحوص الـ security headers + cookies + TLS + أسرار الـ JS bundles العامة + ملفات مكشوفة شهيرة، + **سجل التفويض** (scan authorization record) في أول التقرير. الـ exit 0 أو 1 حسب النتائج.

```bash
# 2) توليد nonce إثبات الملكية
node dist/cli.js ownership https://your-site.com
```

**المتوقع:** nonce + تعليمات واحدة من طريقين:
- **DNS TXT**: سجل TXT باسم `_anubis-guardian.your-site.com` قيمته `anubis-guardian-challenge=<nonce>` (يفضَّل)
- **ملف ويب**: `https://your-site.com/.well-known/anubis-guardian/<nonce>` يرجّع 200 والـ nonce في الجسم

```bash
# بعد النشر — التحقق:
node dist/cli.js ownership https://your-site.com --check <nonce>     # المتوقع: exit 0 verified
# nonce غلط → exit 1. ده اختبار سلوك مقصود.

# 3) L2/L3 — بس بعد التحقق
node dist/cli.js scan-url https://your-site.com --level 2 --ownership-token <nonce>
node dist/cli.js scan-url https://your-site.com --level 3 --ownership-token <nonce>
```

**المتوقع:**
- **L2** = L1 + discovery (`.env`/`.git`/directory listing/TRACE/Swagger/sourcemaps)
- **L3** = L2 + **Supabase live anon probe** (GET فقط: جدول بيرجع صفوف من غير auth ⇒ `URL-060` HIGH — RLS مش شغال في الإنتاج؛ RLS شغال ⇒ `URL-908` INFO)
- **أي محاولة L2/L3 على دومين عام من غير nonce متحقق → exit 2 قبل أي طلب شبكة** — ده البوابة القانونية، جرّبها عمدًا للتأكد:
  ```bash
  node dist/cli.js scan-url https://your-site.com --level 2
  echo "exit = $?"    # المتوقع: 2
  ```

```bash
# 4) الحتمية في Mode 2 — الـ capture
node dist/cli.js scan-url https://your-site.com --capture cap.json --level 1
node dist/cli.js scan-url https://your-site.com --from-capture cap.json --level 1
```

**المتوقع:** إعادة التحليل من نفس الـ capture = نفس الـ findings بايت-ببايت **وصفر طلبات شبكة**.

### A3 — اختبار v1.0 الجديد | v1.0 features

```bash
# الفحص التفاضلي المُقيَّد (IDOR) — يشتغل بس L3 + ملكية متحققة + هويتين منك
node dist/cli.js scan-url https://your-site.com --level 3 --ownership-token <nonce> \
  --active-tests --identity-a "Cookie: session=<PRIVILEGED>" --identity-b "Cookie: session=<RESTRICTED>"
```

**المتوقع:** GET فقط، ≤24 endpoint، قيم الهويات **مش بتتخزن في أي ملف**، وفرق صلاحيات حقيقي ⇒ `URL-061 HIGH` + `needs_confirmation`.

```bash
node dist/cli.js init-zap https://staging.your-site.com   # بدل تضمين DAST — config ZAP قابل للمراجعة
```

---

## الجزء الثاني — دمج Business-OS | Part B — Business-OS Integration

### B1 — الشكل الموصى به: child process (بدون أي استضافة)

الأداة = CLI محلي Node. **مفيش سيرفر، مفيش daemon، مفيش hosting** — Business-OS (الديسكتوب) يشغّلها كعملية ابن وياخد الـ JSON. ده الشكل المجرّب والأكثر عزلًا (لو الأداة crashged، تطبيقك مستمر):

```js
// داخل الـ main process في Business-OS (Electron/NW.js/Tauri sidecar)
import { spawn } from "node:child_process";
import path from "node:path";
import fs from "node:fs";

export function runAnubisScan(projectPath, { onDone, onError } = {}) {
  const cli   = path.join(RESOURCES_DIR, "anubis-guardian", "dist", "cli.js");
  const out   = path.join(TMP_DIR, `anubis-${Date.now()}.json`);
  const child = spawn(process.execPath,               // نفس Node المدمج في Business-OS
    [cli, "scan", projectPath, "--format", "json", "--output", out],
    { cwd: path.dirname(cli), env: { ...process.env, NO_COLOR: "1" } });

  child.on("close", (code) => {
    try {
      const r = JSON.parse(fs.readFileSync(out, "utf8"));
      onDone({ exitCode: code, score: r.score, grade: r.grade,
               summary: r.summary, findings: r.findings,
               notCovered: r.coverage?.classes_not_covered });
    } catch (e) { onError(e); }
  });
  child.on("error", onError);
  return child;   // خزّنه عشان تقدر تلغي: child.kill()
}
```

**عقد الـ JSON** (ثابت ومضمون بالاختبارات):
```jsonc
{
  "tool": "anubis-guardian", "version": "1.0.0",
  "advisory_snapshot": "2026-10",
  "target": { "mode": "codebase", ... },
  "score": 0–100, "grade": "A"–"F",
  "summary": { "critical": n, "high": n, "medium": n, "low": n, "info": n },
  "coverage": { "classes_covered": [...], "classes_not_covered": [...] },
  "score_breakdown": [...],
  "findings": [ { "id": "SUPA-001", "title", "file", "line", "evidence",
                  "owasp", "fix", "remediation", "severity", "confidence",
                  "root", "root_cause", "verified" } ],
  "inventory": { ... },
  "meta": { ... }
}
```

**خريطة الـ exit codes لواجهة Business-OS:**

| Exit | المعنى | اقتراح UI |
|---|---|---|
| `0` | نظيف / تحت البوابة | أخضر — score + grade |
| `1` | findings فوق البوابة (`--fail-on`) | برتقالي/أحمر — اعرض التقرير |
| `2` | خطأ استخدام أو بوابة قانونية (مثلاً L2 بدون ملكية) | اعرض stderr كما هو |

**الملفات المطلوب دمجها في حزمة Business-OS:** `dist/` + `skill/` + `README.md` + `LICENSE` (نفس عقد الـ `files` في package.json — snapshot الـ advisories مدموج جوه `dist/` بالفعل). **Mode 1 صفر إنترنت** — `--ai-review` هو الاتصال الخارجي الوحيد وهو اختياري بمفتاح المستخدم.

### B2 — بديل برمجي: import مباشر

```js
import { scan, scanRoots } from "<bundled>/anubis-guardian/dist/engine.js";
const result = scan(projectPath, { /* نفس flags كـ ScanOptions */ });
```

> ممكن، لكن **الـ child process هو الطريق المجرّب بالاختبارات** — يعزل الأخطاء ويمنع أي تعارض مع event loop التطبيق. استخدم الـ import لو محتاج results في نفس الـ process بدون serialization.

### B3 — داخل pipeline البناء في Business-OS

```bash
node anubis-guardian/dist/cli.js scan ./project --fail-on critical --format sarif --output anubis.sarif
```
`exit 1` = فشل البناء (بوابة الجودة) — نفس السلوك في GitHub Actions عبر `init-ci`.

### B4 — checklist الدمج في Business-OS

- [ ] الـ spawn شغال من التطبيق المُعبَّأ (`process.execPath` + مسار `dist/cli.js` المدمج)
- [ ] الـ JSON بيترسم: score + grade + العدّاد بالخطورة
- [ ] الإلغاء شغال (`child.kill()`) والفحص الطويل مش بيجمد الـ UI
- [ ] مسارات Windows تمرّر كما هي للـ CLI (الأداة بتطبّع المسارات داخليًا)
- [ ] اختياري: زر "فحص الموقع" يشغّل `scan-url` على **L1 فقط** افتراضيًا — أي مستوى أعلى يطلب nonce من المستخدم صاحب الدومين

---

## الجزء الثالث — نموذج النتائج (انسخه، املأه، ابعتله) | Part C — Results Template

```markdown
## نتائج اختبار Anubis Guardian v1.0.0 — <التاريخ>

### الجزء A — الأداة
| # | الاختبار | المتوقع | الفعلي | النتيجة |
|---|---|---|---|---|
| A0 | npm test كاملة | كل المراحل خضرا + exit 0 | | ☐ PASS ☐ FAIL |
| A1-1 | scan تقرير طرفية | score + grade + classes-not-covered | | ☐ PASS ☐ FAIL |
| A1-2 | determinism (diff مرتين) | DETERMINISTIC ✓ | | ☐ PASS ☐ FAIL |
| A1-3 | --format all + --fix-prompt | الملفات كلها اتولدت | | ☐ PASS ☐ FAIL |
| A1-4 | --fail-on critical | exit 1 على المشروع الملوش / 0 على النظيف | | ☐ PASS ☐ FAIL |
| A1-5 | --ai-review (اختياري) | قسم ai_review + بدون مفتاح exit 2 | | ☐ PASS ☐ FAIL |
| A1-6 | test-authz / init-hook / init-ci | الملفات اتولدت صح | | ☐ PASS ☐ FAIL |
| A2-1 | scan-url L1 | تقرير headers/cookies/TLS + authorization record | | ☐ PASS ☐ FAIL |
| A2-2 | ownership + --check | exit 0 verified بعد نشر الـ nonce | | ☐ PASS ☐ FAIL |
| A2-3 | L2 بدون nonce → exit 2 قبل أي طلب | exit 2 | | ☐ PASS ☐ FAIL |
| A2-4 | L3 (لو عندك Supabase منشور) | URL-060 أو URL-908 + GET فقط | | ☐ PASS ☐ N/A |
| A2-5 | capture → from-capture | نفس الـ findings + صفر شبكة | | ☐ PASS ☐ FAIL |
| A3 | --active-tests / init-zap | URL-061 لو فيه فرق صلاحيات / config اتولد | | ☐ PASS ☐ N/A |

### الجزء B — Business-OS
| # | الاختبار | النتيجة | ملاحظات |
|---|---|---|---|
| B4-1 | spawn من التطبيق المعبأ | ☐ PASS ☐ FAIL | |
| B4-2 | JSON parsed + score معروض | ☐ PASS ☐ FAIL | |
| B4-3 | الإلغاء + عدم تجميد الـ UI | ☐ PASS ☐ FAIL | |
| B4-4 | مسارات Windows | ☐ PASS ☐ FAIL | |
| B4-5 | (اختياري) scan-url L1 من التطبيق | ☐ PASS ☐ FAIL | |

### ملاحظات / outputs غير متوقعة:
<الصق هنا أي output غلط أو سلوك غريب>
```

---

> **بعد ما تبعت النتائج:** أي FAIL هيتصلح فورًا في جولة هوت-فكس، ولو كله PASS نمشي في خطوتي المالك الأخيرتين: `npm publish` الفعلي + نشر BENCHMARKS.md كـ launch material مع حالة Business-OS كأول دراسة حالة حقيقية.
>
> **After you send the results:** any FAIL gets an immediate hot-fix round; if all PASS, we move to the final owner steps — the actual `npm publish` and publishing BENCHMARKS.md + the Business-OS case study as launch material.
