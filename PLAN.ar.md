# Anubis Guardian — الخطة الرسمية (بالعربية)

> **أداة مفتوحة المصدر للفحص الأمني لمشاريع الـ vibe coding المبنية بالذكاء الاصطناعي**
>
> الحالة: `اتسلم v1.0 — Step 0 ✅ · v0.1 ✅ · v0.2 ✅ · v0.3 ✅ · v0.4 (Mode 2) ✅ · v1.0 الإصدار العام ✅ — الوضعان + هندسة الإصدار اكتملوا` · المرجع الأصلي: `v2.1` · الرخصة: `MIT` · التاريخ: 2026-10
> الوضعان: **Mode 1 — فحص ملفات الكود** (متاح) · **Mode 2 — الفحص الأونلاين بالرابط** (اتسلم في v0.4)
> التنفيذ: TypeScript / Node ≥ 18 · التوزيع: المصدر + جاهزية npm كاملة (`anubis-guardian` — workflow النشر متسلم: Trusted Publishing + provenance + SBOM) + Agent Skill
>
> نفس الخطة بالإنجليزي: [`PLAN.en.md`](PLAN.en.md) · سجل التصميم التفصيلي ثنائي اللغة + Decision Log: [`docs/PLAN.master.md`](docs/PLAN.master.md)

---

## 1. الملخص التنفيذي

**Anubis Guardian** (اسم مستوحى من الأسطورة المصرية القديمة — حارس البوابات وحامي الأسرار) أداة فحص أمني مفتوحة المصدر متصممة لعصر المشاريع المبنية بالذكاء الاصطناعي. المطورين النهارده بيطلّعوا تطبيقات Next.js وباك-إند NestJS وأنظمة Supabase مولّدة بـ AI agents في أيام بدل شهور — لكن السرعة دي بتيجي بنمط أخطاء أمنية ثابت ومتكرر: مفاتيح API مكشوفة، بيانات اتصال قاعدة البيانات رايحة من الفرونت-إند، Row-Level Security ناقصة، JWT مخزن في `localStorage`، وملفات config مرفوعة على GitHub، وGitHub Actions بدون تثبيت SHA. السكينرات الموجودة (Semgrep وTrivy وGitleaks) أقوياء لكنهم عامين — مش متصممين لنمط الفشل ده، ومش ودودين لمطورين مش متخصصين أمن.

الأداة بتقفل الفجوة دي: بتشتغل **CLI** وكمان **Agent Skill** (`SKILL.md`) أي AI coding agent — Claude Code أو Cursor أو Codex أو Windsurf — يقدر يحمّلها وينفذها. وليها وضعان: فحص ملفات المشروع (Codebase Mode)، أو فحص موقع منشور بالرابط (URL Mode بمستويات L1–L3 مع إثبات ملكية). الناتج تقرير واحد قابل للتنفيذ: درجة أمن من 100، ونتائج مرتبة بالخطورة، وإصلاح ملموس لكل نتيجة.

الفلسفة هي **deterministic-first**: طبقات الفحص الأساسية (الأسرار، تاريخ git، الـ playbooks، SAST-light) كلها قواعد صرفة بتشتغل أوفلاين في ثواني بدون أي تكلفة API. ونتائج الاعتماديات بتتحسب ضد **advisory snapshot مدمج مع كل إصدار** من OSV.dev — فعلى النحو التالي: "نفس الكود + نفس إصدار الأداة = نفس الدرجة" بالظبط. وطبقة AI Review اختيارية (LLM + verifier مستقل) بتتضاف فوق ده في v0.3 للتحليل العميق — ببروتوكول تقنيع + بيانات غير موثوقة صارم.

**ليه TypeScript؟** المشاريع المستهدفة هي Next.js وNestJS — يعني Node موجود أصلًا في بيئة أي مشروع هنفحصه، فمش هنحمّل runtime تاني. و`npx` هي الـ UX الطبيعية لجمهور JS/TS. وتحليل الـ AST للـ TS/JS أسهل بـ `ts-morph`. وبيئات الـ agents (Claude Code / Cursor) شغالة على Node — فالأداة والـ skill بيشاركوا نفس الـ runtime. القاعدة: نفس لغة الجمهور.

## 2. Non-Goals — عقد النطاق

أي فكرة جديدة لازم تعدي على الـ Decision Log وبند roadmap صريح — مفيش إضافة صامتة للخطة.

| مش مغطى | بالتصميم |
|---|---|
| منطق الأعمال والدفع | جزئيًا عبر طبقة الـ AI الاختيارية + مراجعة بشرية — عمره ما حكم آلي |
| DAST عام / fuzzing واسع | الـ L3 مُقيَّد جدًا؛ البديل توليد config جاهز لـ ZAP baseline |
| الامتثال (SOC2 / PCI / HIPAA) | خارج النطاق |
| لغات غير JS/TS | خارج نطاق القواعد المدمجة — الـ Semgrep adapter بيغطيها |
| إصلاح تلقائي | suggested diffs بس — **مفيش تطبيق أي حاجة بدون موافقة بشرية صريحة** |

## 3. تغطية الثغرات

### 3.1 المتحقق — v0.2 (الإصدار الحالي)

| المجال | الفحوص |
|---|---|
| الأسرار | أنماط مفاتيح منسّقة؛ **SUPA-001** service_role بـ decode القيمة + reachability؛ **HDR-001** بيانات DB في الهيدر (receiver-first؛ وربط multi-root بين root اتنين ⇒ CRITICAL متأكد)؛ **SEED-001** باسوردات الـ seeders (استخراج عمود الباسورد من SQL INSERT / docker-compose / قيم حقيقية في `.env.example`)؛ ملفات `.env` مرفوعة |
| تاريخ git والملفات | أسرار في الـ history (`git log -p`)؛ env اتقدمлит بعدين اتحذف؛ تدقيق `.gitignore`؛ جرد الملفات الحساسة (dumps / backups / `.npmrc` / service-account / `tfstate` / مفاتيح SSH) |
| الاعتماديات | **DEP-001** CVEs ضد snapshot مدمج من OSV.dev (124 advisory H/C على 16 حزمة أساسية)؛ **DEP-002** حزم معروفة بخبث (OSV MAL)؛ **DEP-003** typosquat (مسافة Damerau ≤ 2 مقابل ~450 اسم شائع)؛ **DEP-004** غير محلولة + مفيش lockfile (مرشح هلوسة)؛ **DEP-005** slopsquat ورا `--online` |
| SAST-light + crypto | **SAST-001** SQLi بالـ concat، **SAST-002** HTML خطير (مع تتبع local-const)، **SAST-003** eval/exec بالاستكمال، **SAST-004** hashing ضعيف؛ **CRYPTO-001** `Math.random` للتوكنات/OTPs (مُرقّاة من v0.3 ببيانات Step 0: 11% من العينة) |
| Supabase playbook | **SUPA-R01** RLS ناقص (HIGH + `needs_confirmation` → CRITICAL بتأكيد schema-export/live-probe)، **R02** `USING (true)`، **R03** views بدون `security_invoker`، **R04** `SECURITY DEFINER` بدون `search_path`، **R05** انحراف الداشبورد عن الـ migrations بـ schema dump بتشغّله إنت، **R06** سياسات بدون user-scoping، **R07** `storage.objects` بدون RLS، **R08** `verify_jwt=false` في Edge Functions |
| Next.js playbook | **NEXT-001** أسرار عبر `NEXT_PUBLIC_*` (مع استثناء decode مفاتيح anon)، **NEXT-002** توكنات في web storage، **NEXT-003** flags الكوكيز، **NEXT-004** endpoints بتعدّل بدون auth في الملف (بمراعاة الـ middleware، على مستوى الملف) |
| NestJS playbook | **NEST-001** controllers بدون حماية (بيحترم APP_GUARD العام)، **NEST-002** CORS wildcard، **NEST-003** helmet ناقص، **NEST-004** throttler ناقص |
| CI / سلسلة التوريد | **CI-001** actions بدون SHA pinning، **CI-002** `pull_request_target`، **CI-003** حقن سكريبت (بما فيه block-scalar)، **CI-004** صلاحيات زايدة؛ **DOCKER-001** root، **DOCKER-002** `:latest`، **DOCKER-003** أسرار في ARG — حزمة الـ CI هي رقم 1 بالبيانات المقاسة (22% من عينة Step 0) |
| الجرد (Recon) | `inventory.json`: مسارات / server actions / controllers مع حالة الـ guard / جداول Supabase وحالة RLS / RPC / Edge Functions / أحداث Socket.IO / webhooks — بيتغذى منه الـ authz matrix في v0.3 |

### 3.2 المتحقق — v0.3 (rule packs II + taint-lite + بيئة الـ agent + AI Review)

| الفحص | الهدف |
|---|---|
| `LOGS-001` أسرار متسربة في الـ logs | v0.3 |
| `SUPA-002` `user_metadata` جوه سياسات RLS · `SUPA-003` RPC/Edge بـ `service_role` بدون auth | v0.3 |
| `AUTH-001` الاعتماد على الـ middleware بس في الـ auth (مربوط بالـ matcher) | v0.3 |
| `MASS-001` mass assignment (`data: req.body` بدون whitelist) | v0.3 |
| `WS-001` Socket.IO gateways بدون auth (`io.use`) | v0.3 |
| `WEBHOOK-001` webhooks بدون تحقق توقيع | v0.3 |
| `JWT-001/002` `jwt.decode` لقرارات الأمان / `algorithms` مفتوحة / `ignoreExpiration` | v0.3 |
| `SWAGGER-001` Swagger/OpenAPI متاح في production | v0.3 |
| Taint-lite (نطاق ملف واحد + استيراد واحد، سقف MEDIUM، clean-cases إلزامية): SSRF / open redirect / path traversal / command injection / reflected XSS | v0.3 |
| كوكي مش HttpOnly فعلًا + heuristic للـ CSRF (Next.js) | v0.3 (heuristic) |
| Authz Matrix (تجريبية، بتتغذى من `inventory.json`) + differential IDOR مُقيَّد | v0.3 / v1.0 |
| URL Mode الـ L1–L2 (وL3 مُقيَّد) | v0.4 |

### 3.3 المتحقق — v0.4 (الإصدار ده: URL Mode / Mode 2)

| الفحص | المستوى | البوابة |
|---|---|---|
| `URL-001/002/003` HTTP بدون TLS · بروتوكول TLS ضعيف · شهالة منتهية/قاربت على الانتهاء/غير صحيحة | L1 | لا شيء |
| `URL-010..015` نقص CSP / HSTS / الحماية من clickjacking / nosniff / referrer / permissions | L1 | لا شيء |
| `URL-020/021/022` كوكيز بدون Secure / HttpOnly (اسم session ⇒ HIGH) / SameSite | L1 | لا شيء |
| `URL-030/031` كشف إصدار Server وX-Powered-By | L1 | لا شيء |
| `URL-040` **سر متشحّن جوه ملف JS عام** (service_role بفك دور الـ JWT، Stripe live، AWS، OpenAI، GitHub، Google، Slack، مفاتيح خاصة، DB URLs — مُقنَّع + rotate-first) | L1 | لا شيء |
| `URL-041/043` endpoints داخلية في الـ bundles · إشارات sourceMappingURL (نصيحة) | L1 | لا شيء |
| `URL-050/051/052/053` مكتبة `.env` (بقيم أسرار ⇒ CRITICAL) / `.git` / SQL dumps والنسخ / composer | L2 | **ملكية متحققة** |
| `URL-054..057` directory listing · TRACE (XST) · أوامر خطرة في `Allow` · Swagger/GraphiQL مكشوفة | L2 | ملكية متحققة |
| `URL-042` source maps بتنزّل الكود الأصلي (محتوى فيه أسرار ⇒ HIGH) | L2 | ملكية متحققة |
| `URL-901` mapping لأسطح admin/login (info) | L2 | ملكية متحققة |
| `URL-060` **الـ Supabase live anon probe** — `GET /rest/v1/<table>?limit=1` رجّع صفوف ⇒ الـ RLS مش شغال في الإنتاج (GET فقط، ملكية متحققة إجباري) | L3 | **ملكية متحققة مفروضة** |

L1 مكافئ-للمتصفح بالبناء (الصفحة + robots.txt + sitemap.xml + security.txt + ملفات الـ JS العامة اللي الصفحة بتحمّلها — **صفر probing**، ومثبت ببوابة سجل الطلبات في الـ acceptance). وL2+ بيرفض أي دومين عام بدون بوابة بـ exit 2 **قبل أي طلب واحد**. وكل تقرير فيه سجل تفويض الفحص + ملصق الملكية. ونفس عقد المخرجات مع إرشاد `Code map:`؛ وإعادة التحليل من `--from-capture` متطابقة بايت-ببايت بصفر شبكة.

كل مرشحي rule packs II اتقاسوا ≤ 1% في العينة العلنية (100 مشروع) — قيمتهم بتتأكد في الـ dogfooding الحقيقي، وعشان كده نزلوا بعد الأولويات المؤكدة بالبيانات.

**كمان اتم في v0.3:** **فحوص بيئة الـ agent** (AGENT-001..004: MCP بدون تثبيت إصدار، أسرار جوه config الـ agent، صلاحيات wildcard/bypass، hooks بتشغل كود بعيد)، **طبقة AI Review مع verifier مستقل** (`--ai-review`، مطفية افتراضيًا: تقنيع قبل الإرسال للـ LLM + بروتوكول بيانات غير موثوقة + 4 بوابات تحقق deterministic؛ الدليل المهلوَل والملفات الناقصة ومعرّفات القواعد المجهولة بترفض؛ ونتائج الـ AI سقفها HIGH)، **مصفوفة الصلاحيات + quarantine** (`test-authz`: اختبارات Supertest/Playwright فاشلة-بالتصميم والأداة عمرها ما بتشغلها)، **guard hook مثبّت الإصدار** (`init-hook`: منع service_role في كود الـ client وSQL اللي بيقتل RLS والأسرار في `.env` لحظة الكتابة)، و**الـ Agent Skill الكاملة** (`skill/SKILL.md`). والقبول: `npm test` بيقلب 6 بوابات — build، honeypot **49/49 بذرة**، clean corpus **صفر FP (100/A)**، SARIF، وacceptance v0.2 + v0.3 (determinism للـ AI review بمزوّد canned، بوابات الـ verifier على مستوى الـ wire، منع/سماح الـ hook، وتوليد الـ authz matrix والـ canaries).

## 4. وضعا التشغيل

### Mode 1 — فحص ملفات الكود (متاح الآن)

`anubis-guardian scan <paths...>` — أوفلاين، ثابت فقط، وعمره ما بينفذ كود المشروع المفحوص. وmulti-root (`scan ./frontend ./backend`) بيربط النتائج بين الـ roots. ودعم المونوريبو عبر `--workspaces`. وقواعد مؤسسية مخصصة عبر `--rules-dir`. ومرجع الأوامر الكامل في الـ [README](README.md).

### Mode 2 — الفحص الأونلاين بالرابط (اتسلم في v0.4)

فحص موقع منشور **بالرابط** بثلاثة مستويات متدرجة:

- **Level 1 — مسح خارجي passive (الافتراضي):** طلبات مكافئة للمتصفح بس — security headers، TLS، cookie flags، + تنزيل وتحليل ملفات JS العامة (الأسرار المتشحّنة بتتشاف هنا — بالظبط زي ما المتصفح شايفها).
- **Level 2 — discovery:** فحص مسارات حساسة (`.env` مكشوف، `.git`، directory listing) — للدومينات العامة **إثبات الملكية إجباري**؛ والتصريح الذاتي محصور على localhost/staging ومعلَّم دايمًا.
- **Level 3 — نطاق v0.4 = L2 + الـ Supabase live anon probe** (GET قراءة فقط، وملكية متحققة مفروضة — عمره ما بيتشغل بالـ flag لوحده). **v1.0 نفّذت قرار النطاق النشط بفرعيه معًا:** الفحص التفاضلي المُقيَّد (`--active-tests` — GET فقط، ملكية متحققة، هويتين testing من المالك، سقف 24 endpoint، قيم الهويات عمرها ما بتتخزن) **و** `init-zap` اللي بيولّد ZAP baseline config قابل للمراجعة — والمحرك لسه من غير DAST بالتصميم.

**إثبات الملكية:** DNS TXT record باسم `anubis-guardian-challenge` أو nonce على `/.well-known/anubis-guardian/`. وكل تقرير URL بيحمل طريقة إثبات الملكية المستخدمة. وطبقة الـ URL فيها consent banner وrate limiting وrobots awareness وسجلات تفويض.

> **الوضعان اتنين اتصلموا.** Mode 1 اكتمل عبر v0.3، وMode 2 نزل في v0.4 بالترتيب المثبّت بالظبط. الـ URL Mode هو "تكافؤ تنافسي" (ملاحظة الصراحة v1.5) — التمييز الحقيقي هو إثبات الملكية المتحقق منه + نفس عقد المخرجات (fix-prompt + إرشاد `Code map:` "فين في الكود").

## 5. المعمارية

```
anubis-guardian/
├── src/
│   ├── engine.ts / walk.ts / score.ts / types.ts   # المحرك، الـ scoring، عقد البيانات
│   ├── urlmode/       # v0.4 Mode 2: fetcher الـ capture، بوابة الملكية، فحوص L1/L2/L3، المحلّل
│   ├── rules/         # تنفيذ قواعد الطبقات 1/2/3/4/5 (ملف لكل مجال)
│   ├── report/        # renderers حتمية: terminal, md, sarif, html, compact, fix-prompt
│   ├── inventory.ts   # جرد الـ Phase 0
│   ├── adapters.ts    # gitleaks / osv-scanner / semgrep (اختيارية) + update-advisories
│   ├── rulesdir.ts    # DSL القواعد المؤسسية --rules-dir (clean_cases مطلوبة)
│   ├── initci.ts      # مولّد الـ workflow (SHA pins حقيقية عبر git ls-remote)
│   └── advisory/      # advisory snapshot مدمج من OSV.dev + قائمة الحزم الشائعة
├── skill/SKILL.md     # صيغة Agent Skills لـ IDE agents
├── studies/step0-pattern-study/   # دراسة البيانات (100 مشروع — RESULTS.md)
└── tests/             # honeypot (49 بذرة) + clean corpus + SARIF + acceptance v0.2/v0.3 + mode2/ (v0.4)
```

اعتمادية runtime واحدة (`commander`). Node ≥ 18. والـ determinism عقد صلب: مفيش timestamps في الـ findings، و`findings.json` و`fix-prompt.md` متطابقين بايت-ببايت لنفس المدخلات + إصدار الأداة — وفي Mode 2: نفس الـ **capture bundle** ⇒ نتائج متطابقة بايت-ببايت (`--from-capture` بصفر شبكة) — لأن الـ wire الحي مش حتمي بطبيعته، لكن الخط الحتمي.

## 6. الخطورة والدرجات

**نموذج الخطورة** — الخطورة مربوطة بالأثر المقاس، مش بعدد القواعد:

- **مفيش CRITICAL من غير تأكيد مستقل** — الإشارة الـ deterministic (مثلًا: RLS ناقص على جدول public) بتنزل **HIGH + `needs_confirmation`**؛ والـ CRITICAL بس مع تأكيد حقيقي: schema export بتشغّله المالك، أو live probe، أو cross-root linkage.
- نتائج الثقة المنخفضة وINFO عمرها ما بتخصم.

**الدرجة:**

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)     درجات A–F
```

سقوف حسب السبب الجذري: أول finding لنفس السبب الجذري بيخصم كامل، والتكرار بيضيف +10% بس، والمجموعة مسقوفة على 2× — ملف `.env` واحد متسرب مش بيتحول لـ 40 خصم بسبب 40 مفتاح. و`score_breakdown` بيظهر كل خصم وسببه.

**بوابات الـ CI:** `--fail-on high|critical` و`--fail-on-cve` (exit 1/0 متحقق في الـ acceptance). والـ workflow المولّد من `init-ci` بيمنع أي PR فيه CRITICAL.

## 7. عقد المخرجات

كل renderer هو عرض حتمي فوق نفس `findings.json`:

| المخرج | المستهلك |
|---|---|
| التيرمينال / `--format md` | المطور، فورًا |
| `findings.json` | الـ CI والداشبورد والتكاملات المستقبلية — فيه `confidence` و`fingerprint` و`suppression` و`coverage.classes_covered / classes_not_covered` |
| `--sarif` (SARIF 2.1.0) | تاب Security / code scanning في GitHub |
| `--fix-prompt fix.md` | أي AI agent — برومبت إصلاح حتمي بـ guardrails rotate-first ("ممنوع لمس tests" و"دوّر قبل الحذف") |
| `--compact` | ملخص موفّر للتوكِن لسياقات الـ agents |
| `--html` | تقرير كامل قابل للمشاركة |
| `--inventory inventory.json` | الـ authz matrix في v0.3 + التدقيق المؤسسي |

والتقنيع إجباري في كل مخرج: دليل السر = النوع + الموقع + أول 4 حروف + بادئة sha256 — والقيمة الكاملة عمرها ما بتتكتب في أي مكان.

## 8. الأمان — النموذج التهديدي للأداة نفسها (ملخص)

- **مفيش تنفيذ لكود المشروع المفحوص** (§9.7 في الخطة الأم): قراءة ملفات + git plumbing بس؛ والاختبارات المولّدة/مجلدات الـ quarantine اللي بتشغلها المالك مش الأداة.
- **التقرير نفسه ممنوع يسرب** (§9.2): تقنيع إجباري في كل حتة، بما فيها artifacts الـ CI والـ SARIF.
- **بروتوكول طبقة الـ AI** (§9): تقنيع قبل إرسال أي حاجة للـ LLM، بروتوكول بيانات غير موثوقة ضد حقن التعليمات، suggested-diff بس — مفيش auto-apply.
- **القواعد المؤسسية كسلسلة توريد** (§9.4): `--rules-dir` بيشترط clean-cases لكل قاعدة؛ والـ CRITICAL المؤسسي بيتفرض عليه `needs_confirmation`؛ **وv1.0 سلّمت `rules-lock`** — تثبيت SHA-256 لكل ملف قواعد، والـ scan بيرفض المعدّل/غير المثبّت، و`--allow-community-rules` بيشتغل معلَّم quarantine في meta؛ والسجل المجتمعي البعيد هيبني فوق نفس الميكانيزم.
- **إساءة استخدام URL Mode** (§9.5): مستويات متدرجة، بوابات إثبات ملكية، rate limits، سجلات تفويض.
- **سلسلة توريد التوزيع** (§9.6) — **اتسلمت في v1.0:** مولّد SBOM (CycloneDX 1.5) + `.github/workflows/release.yml` (npm Trusted Publishing + provenance attestation + checksums + actions مثبتة بـ SHAs حقيقية) + تعليمات التاج الموقّع؛ وإصدارات الـ hook/plugin مثبّتة بإصدار صريح (عمرها ما `@latest`).
- **تعارض الاسم** ("Anubis" مستخدم في OSS تانية زي TecharoHQ/anubis): دايمًا الاسم الكامل **Anubis Guardian**، وحزمة npm `anubis-guardian`.

## 9. ترتيب الأولويات بالبيانات — دراسة Step 0

قبل الوثوق بالحدس، الأداة قاست النظام البيئي: **100 مشروع عام مبني بالـ AI** (80 بإشارة بناء AI صريحة — Lovable/Bolt/Cursor/Claude/Windsurf/vibe — + 20 AI-default-stack)، **3,403 ملف**، ببروتوكول موثّق قابل للتكرار (`studies/step0-pattern-study/RESULTS.md`).

| النمط | التكرار | القرار |
|---|---|---|
| GitHub Actions بدون pinning | **22%** (91 hit) | حزمة الـ CI → رأس v0.2 ✅ |
| `Math.random` للتوكنات/OTPs | **11%** (136 hit) | CRYPTO-001 مُرقّاة v0.3 → **v0.2** ✅ |
| `dangerouslySetInnerHTML` | 7% | مغطاة أصلًا (SAST-002) |
| SQL concat / RLS `USING (true)` / service_role / `.env` مرفوع | 3% لكل واحدة | مغطاة أصلًا |
| LOGS / SUPA-002/003 / WS / SWAGGER / MASS / WEBHOOK / JWT / AUTH | ≤ 1% لكل واحدة | فضلت v0.3 — القيمة بتتأكد في الـ dogfooding مش بتردد العلني |

والعينة الخام (`sweep.json` و`totals.json` وقائمة الاستنساخ) محفوظة لإعادة التحليل ولبناء الـ labeled recall corpus عند v1.0.

## 10. خارطة الطريق وسجل حالة البناء

> قاعدة التتبع (طلب المالك): السجل ده بيتحدّث بعد **كل** مرحلة تكتمل — وعلامة ✅ من غير دليل تحقق موثق ممنوعة. الحالة الحية بتعكس الخطة الأم.

| المرحلة | الحالة | الدليل |
|---|---|---|
| الخطة v1.8 — 8 جولات مراجعة (57 بند تصميم محكوم) | ✅ | Decision Log |
| v0.1 — نواة فحص الكود (الشرائح أ→هـ) | ✅ أكتوبر 2026 | Honeypot 13/13 · clean صفر FP (100/A) · determinism byte-identical · scan 0.08s · masking متحقق |
| Step 0 — أداة القياس (32 نمطًا مرشحًا) | ✅ ضمن v0.1 | `CANDIDATE_PATTERNS.yaml` + `measure.mjs` |
| Step 0 — المسح الفعلي (100 مشروع) | ✅ أكتوبر 2026 | 100 repo / 3,403 ملف — `RESULTS.md` |
| **v0.2 — العمق والتكاملات** | ✅ **أكتوبر 2026** | Honeypot 30/30 (2 roots) · clean صفر FP (100/A) · SARIF verifier · acceptance كاملة (بما فيها byte-identical لـ `findings.json` + `fix-prompt.md`) |
| **v0.3 — Agent Skill + AI Review** (taint-lite · authz matrix · rule packs II · guard hook) | ✅ **أكتوبر 2026** | Honeypot 49/49 · clean صفر FP (100/A) · SARIF + acceptance v0.2/v0.3 خضرا: الـ verifier بيرفض المهلوَل/الملفات الناقصة/القواعد المجهولة، التقنيع متحقق على الـ wire، نتائج الـ AI مسقوفة على HIGH، منع الـ hook شغال، والـ authz matrix + canaries مولّدة (عمرها ما اتنفذت) |
| **v0.4 — URL Mode / Mode 2** (L1 passive + L2 بإثبات ملكية + L3 probe الـ Supabase) | ✅ **أكتوبر 2026** | `npm test` السلسلة كاملة خضرا: mode2 verify **33/33** (سيرفر بثغرات مزروعة: ‎.env بـ CRITICAL، ‎.git بـ HIGH، SQL dump بـ CRITICAL، directory listing، TRACE، Swagger، sourcemap، سرّين في الـ JS bundle بـ CRITICAL، الكوكيز، الهيدرز، احترام robots-skip، والتقنيع) + acceptance **47 بوابة**: إثبات إن L1 passive فعليًا من سجل الطلبات (مفيش probing خالص) · رفض L2 لدومين عام بدون بوابة ⇒ exit 2 قبل أي طلب · رفض checkbox للدومينات العامة ⇒ exit 2 · رفض L3 بالـ self-attestation ⇒ exit 2 · تحقق ‎.well-known حي + اختبارات وحدة لـ DNS TXT · تحليل probe الـ Supabase (GET فقط) من ردود ملتقطة · حتمية from-capture بايت-ببايت وإعادة تحليل بصفر شبكة · كل الـ renderers (SARIF/fix-prompt/md/compact/html) على نتائج URL · rate limiting · clean control بالظبط 90/A · أمر ownership |
| **v1.0 — الإصدار العام: rules-lock + الفحص التفاضلي المُقيَّد + init-zap + SBOM/provenance + METHODOLOGY/CONTRIBUTING + BENCHMARKS.md (مقاسة فقط) + اختبار install→report** | ✅ **تمت** — acceptance v1.0: 45/45 بوابة · BENCHMARKS.md: 14 قياسًا (honeypot 49/49 · clean 0 FP · NodeGoat 16 · Juice Shop 121) | `download/anubis-guardian-v1.0.zip` |
| v1.0 — خطوات المالك: `npm publish` الفعلي + التحقق الميداني على Business-OS (أول dogfood فعلي، مؤجل بوعي لآخر المراحل) | ⬜ المالك | — |

**البوابات المتبقية:**

| المرحلة | بوابة الخروج (Acceptance) |
|---|---|
| v0.3 | "audit this project" جوه IDE بتشغل الأداة end-to-end وتقترح suggested diffs لأهم النتائج — **من غير تطبيق أي حاجة بدون موافقة بشرية صريحة** |
| ~~v0.4~~ ✅ | **اتحققت:** نفس عقد المخرجات على نتائج الـ URL (الـ fix-prompt فيه تعليمة mapping الـ endpoints للكود) · L2 بيرفض بدون بوابة (مثبت: دومين عام، checkbox، وL3 بالـ self-attestation) · طريقة الملكية + سجل التفويض في كل تقرير · قبول الـ demo deployment: كل هيدر ناقص مزروع + ‎.env مكشوف + سر في الـ JS bundle اتكشفوا |
| v1.0 | ✅ install→أول تقرير متحقق منه من التاربول المعبأ (أقل من دقيقتين — بوابة N4) · BENCHMARKS.md منشور بأرقام مقاسة فقط · **قرار L3 النشط منفّذ** (`--active-tests` المُقيَّد + توليد config لـ ZAP) · npm publish جاهزة (الخطوة على المالك) |

## 11. التحقق والاختبار

الـ Honeypot (30 بذرة مزروعة عبر Next.js+Supabase app وNestJS API) هو **بوابة الانحدار الدائمة** — كل إصدار لازم يمسك 100% من البذور. وحدوده الصريحة: هو بيثبت إن الإصدار الجديد ماكسرش حاجة، لكن بيثبتش حاجة عن الـ real-world recall — لأننا اللي زرعنا الثغرات اللي الأداة مبنية تمسكها. عشان كده التحقق طبقات:

| الطبقة | بتقيس إيه | الهدف |
|---|---|---|
| Honeypot (30 بذرة) | الانحدار: الإصدار الجديد ماكسرش حاجة | 100% من الـ criticals/highs |
| Labeled AI-corpus (من عينة Step 0) | الـ recall على ثغرات حقيقية إحنا مازرعناهمش | مقاس ومنشور في BENCHMARKS.md — بدون وعد رقمي مسبق |
| تطبيقات عامة فيها ثغرات (Juice Shop / NodeGoat) | sanity للطبقات العامة بس (الأسرار + SAST) — مش مقياس للـ playbooks | مقاس ومنشور |
| Clean corpus (مشاريع AI حقيقية نظيفة) | معدل الإنذارات الكاذبة | أقل من 10% |
| Dogfooding — **Business-OS أولًا** (مشاريع المالك الإنتاجية) | أول إشارة واقعية + مادة launch | بينشر كـ case study |

و`npm test` بيقلب كل البوابات: build + honeypot + clean + SARIF + acceptance. والـ determinism byte-identical وعقد الـ masking بيتأكدوا في كل تشغيلة.

## 12. مبادئ القرار

1. **Deterministic-first** — النواة قواعد أوفلاين؛ وأي حاجة غير حتمية اختيارية ومعلَّمة في `meta`.
2. **مفيش finding من غير evidence** — ومفيش CRITICAL من غير تأكيد مستقل.
3. **الخطورة تتطلب أثرًا** — مربوطة بالأثر الفعلي مش بعدد القواعد المخالفة (ضد alert fatigue).
4. **Rotate-first** — كل سر مكتشف معاه خطوات تدوير خاصة بمزوّده، مش "شيل المفتاح".
5. **Suggested diffs فقط** — الأداة عمرها ما بتعدّل مشروعك؛ وحتى طبقة الـ AI بتعترض والبشر بيطبقوا.
6. **نفس لغة الجمهور** — TypeScript/Node لأن هنا بتاع المشاريع المستهدفة والـ agents.
7. **قواعد عامة + playbooks قابلة للتوسعة** — قواعد الأسرار/التاريخ/CI/الاعتماديات/SAST عامة مستقلة عن أي framework؛ والـ playbooks العميقة (Supabase/Next.js/NestJS) بتغطي أعلى ستاكات الـ vibe coding تكرارًا أولًا — وبيانات Step 0 هي اللي بتقود أي توسعة.
8. **النطاق مجمّد** — الأفكار الجديدة بتدخل عبر الـ Decision Log وبند roadmap صريح، عمرها ما بصمت.
