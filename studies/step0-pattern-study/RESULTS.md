# Step 0 — Pattern-Frequency Results (Full Sweep)

**Sample:** 100 public project(s) (3,403 source files measured) · collected 2026-10-24 · GitHub search API (queries documented below) · shallow clones (depth 1)
**Population:** 80 AI-tool-built (lovable/bolt/cursor/claude/windsurf/vibe signals) + 20 AI-default-stack (Next.js+Supabase) · tags: lovable=15 · bolt=4 · claude=6 · windsurf=5 · cursor=44 · vibe=6 · stack=20

> **منهجية القياس:** عدّاد grep حتمي offline — كل رقم هو **تكرار النمط النصي** مش حكم أمني مُتحقق منه؛ الأنماط "leads" بتحدد أولوية الـ rule packs، والقياس الفعلي بيحصل جوه المحرك بقواعده الكاملة + clean-cases. الـ history check معطّل فعليًا في الاستنساخ الضحل (depth 1) — env_in_git_history هنا أقل من الواقع.

| Rank | Pattern | Projects affected | % of sample | Total hits | AI-built (80) | Stack (20) |
|---|---|---|---|---|---|---|
| 1 | GitHub Actions using tag/branch refs instead of SHA pinning (CI-001 lead) (`ci_unpinned_actions`) | 22/100 | **22%** | 91 | 22/91 | 0/0 |
| 2 | Math.random for tokens/OTPs (v0.3 CRYPTO-001 lead) (`math_random_tokens`) | 11/100 | **11%** | 136 | 8/128 | 3/8 |
| 3 | dangerouslySetInnerHTML usage (review non-literals) (`dangerous_html`) | 7/100 | **7%** | 8 | 6/6 | 1/2 |
| 4 | SQL built by string concatenation (`sql_concat`) | 3/100 | **3%** | 15 | 1/1 | 2/14 |
| 5 | RLS policies USING(true)/WITH CHECK(true) (`rls_permissive`) | 3/100 | **3%** | 5 | 2/3 | 1/2 |
| 6 | JWT-shaped literals in code/env (service_role leads — engine decodes by value) (`service_role_lead`) | 3/100 | **3%** | 3 | 1/1 | 2/2 |
| 7 | .env / .env.production present in worktree (`committed_env`) | 3/100 | **3%** | 3 | 2/2 | 1/1 |
| 8 | env files ever committed (git log --diff-filter=A) (`env_in_git_history`) | 3/100 | **3%** | 3 | 2/2 | 1/1 |
| 9 | AWS access keys (`aws_keys`) | 2/100 | **2%** | 22 | 2/22 | 0/0 |
| 10 | generic credential assignments (api_key/secret/token = long literal) (`hardcoded_secret_generic`) | 2/100 | **2%** | 3 | 1/1 | 1/2 |
| 11 | secret-looking keys under NEXT_PUBLIC_/VITE_/REACT_APP_ (`nextpublic_secret_keys`) | 2/100 | **2%** | 2 | 0/0 | 2/2 |
| 12 | private key material (`private_keys`) | 2/100 | **2%** | 2 | 2/2 | 0/0 |
| 13 | eval/exec/new Function usage (`eval_exec`) | 1/100 | **1%** | 3 | 1/3 | 0/0 |
| 14 | connection URLs with embedded password (`db_url_with_password`) | 1/100 | **1%** | 2 | 0/0 | 1/2 |
| 15 | console.log printing secret-looking vars (LOGS-001 lead) (`logs_secret_leak`) | 1/100 | **1%** | 1 | 1/1 | 0/0 |
| 16 | user_metadata referenced in SQL policies (SUPA-002 lead) (`supabase_user_metadata`) | 1/100 | **1%** | 1 | 0/0 | 1/1 |
| 17 | service_role key inside supabase/functions (SUPA-003 lead) (`supabase_service_role_fn`) | 1/100 | **1%** | 1 | 1/1 | 0/0 |
| 18 | DB credentials sent/received in HTTP headers (`db_creds_in_headers`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 19 | hardcoded passwords in seeders/fixtures (`seeder_credentials`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 20 | auth tokens stored in localStorage/sessionStorage (`jwt_in_localstorage`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 21 | Stripe live keys (`stripe_live`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 22 | MD5/SHA1 hashing (password context judged by engine) (`weak_hashing`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 23 | jwt.decode usage (v0.3 JWT-001 lead) (`jwt_decode_usage`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 24 | .npmrc with _authToken (`npmrc_token`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 25 | terraform.tfstate present (`tfstate`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 26 | cloud service-account JSON with private key (`service_account_json`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 27 | pull_request_target workflow trigger (CI-002 lead) (`ci_pull_request_target`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 28 | Dockerfile FROM :latest tag (DOCKER-002 lead) (`dockerfile_latest`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 29 | NestJS @Body() typed any (MASS-001 lead) (`mass_assignment_lead`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 30 | Socket.IO @WebSocketGateway present (WS-001 lead) (`ws_gateway_presence`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |
| 31 | SwaggerModule.setup present (SWAGGER-001 lead) (`swagger_setup`) | 0/100 | **0%** | 0 | 0/0 | 0/0 |

## Selection protocol (reproducible)

- GitHub search API, unauthenticated, 2026-10-24 — filters: not a fork · size ≤ 20 MB · per_page=80/query · smallest-first cloning · queries:
  - `lovable in:name,description,readme language:typescript`
  - `lovable.dev in:readme language:javascript`
  - `bolt.new in:name,description,readme`
  - `built with v0 in:readme language:typescript`
  - `cursorrules in:name,description`
  - `vibe coding language:typescript`
  - `generated with claude in:readme`
  - `windsurf in:readme language:typescript`
  - `supabase nextjs app language:typescript pushed:>2025-06-01`
  - `supabase nextjs dashboard language:javascript pushed:>2025-06-01`


---

## Data-Driven Conclusions — Rule-Pack Priority (v0.2/v0.3)

> الخلاصة المطلوبة بالتصميم (plan Section 11): جدول التكرار الناتج بيحدد أولوية الـ rule packs. دي القراءة التنفيذية:

| # | القرار | الدليل من المسح | التأثير على الـ roadmap |
|---|---|---|---|
| 1 | **CI pack (CI-001..004) = أعلى أولوية في v0.2** | unpinned Actions في **22%** من العينة (91 hit) — أعلى نمط على الإطلاق؛ مشروع من كل 4.5 مبني بالـ AI عنده workflow بيستخدم refs قابلة للـ hijack | كان مجدول v0.2 (v1.6) — اتأكد بالبيانات وبيترقّى لرأس قائمة v0.2 |
| 2 | **CRYPTO-001 (Math.random tokens) يترقى من v0.3 → v0.2** | **11%** من العينة (136 hit) — تاني أعلى نمط؛ 1 من كل 9 مشاريع بيولّد توكنات/OTPs بمولّد غير آمن | الخطة كانت سابت الجدولة للبيانات صراحة (Decision Log v1.6-C) — البيانات بتقول v0.2 |
| 3 | **قواعد SAST الموجودة متأكدة** | dangerouslySetInnerHTML 7% · SQL concat 3% | مفيش تغيير — v0.1 مغطّاها فعلًا |
| 4 | **الـ secrets الكلاسيكية نادرة في العينة العلنية** (AWS 2% · private keys 2%) لكنها موجودة | الأسرار الحقيقية بتتسرب أقل في المشاريع العلنية — لكن 2% مش صفر، والـ engine موجود في v0.1 | مفيش تغيير — Layer 1/2 يفضلوا الأساس |
| 5 | **RLS/service_role/committed-env ≈ 3% لكل واحدة** | الإشارات موجودة وقابلة للقياس حتى بدون تثبيت تبعيات | Supabase playbook يفضل عمق v0.1 + depth II في v0.2 |
| 6 | **إشارات NestJS صفر في العينة** (no @WebSocketGateway / SwaggerModule / @Body any) | انحياز مجتمع متوقع: Lovable/Bolt/Cursor بينشروا apps واجهة (Next.js) — الـ NestJS backends أقل نشرًا علنيًا | NestJS playbook يفضل v0.2 بقرار الخطة (مش مجتمعة من المسح) — والملاحظة دي نفسها مدخل لتوسيع العينة بعدين |
| 7 | **HDR-001 / SEED-001 niche لكنها فئات أصيلة** | 0% في العينة العلنية — منطقي: أسرار الـ headers بتحصل runtime بين services، مش في كود عام | تفضل القاعدتين المميزتين (rare-but-real) — القيمة في الـ dogfooding على مشاريع حقيقية زي Business-OS |
| 8 | **LOGS-001 / SUPA-002 / SUPA-003 ≤ 1%** | إشارات ضعيفة في العينة العلنية | يفضلوا v0.3 (rule packs II) زي الخطة |

### Caveats (موثّقة للصدق المنهجي)

1. **grep counts ≠ verified findings** — الرقم ده تكرار النمط النصي؛ المحرك بيقيم بـ reachability وconfidence وclean-cases قبل ما يصدر حكم.
2. **shallow clones (depth 1)** — فحص الـ history بيشوف الـ root commit بس؛ env_in_git_history هنا **أقل من الواقع** (المشاريع الكاملة غالبًا عندها تاريخ أطول).
3. **العينة من المشاريع العلنية** — الأسرار الحقيقية أغلبها في مشاريع خاصة/محيطة، فنسب الأسرار هنا floor مش ceiling.
4. **selective survivorship** — المشاريع المنشورة عبر منصات vibe coding علنًا هي الأصغر والأحدث؛ بياس العينة موثّق بالـ queries.
5. عدّاد env_in_git_history يستثني .example/.sample/.template/.development (تصحيح بعد أول تشغيل — كان بيعدّ ملفات الأمثلة).


## Per-project appendix

| Project | Population | Files | Dominant signal |
|---|---|---|---|
| [realizersnetwork/vibe-coding-course](https://github.com/realizersnetwork/vibe-coding-course) | ai-built | 191 | — |
| [ClaireYAhn/Finguard](https://github.com/ClaireYAhn/Finguard) | ai-built | 144 | aws_keys:16 private_keys:1 |
| [abhinavsrivastava779/pnsmemorialschool](https://github.com/abhinavsrivastava779/pnsmemorialschool) | ai-built | 138 | committed_env:1 env_in_git_history:1 |
| [thanseeftrio/client-web](https://github.com/thanseeftrio/client-web) | ai-built | 109 | dangerous_html:1 math_random_tokens:1 |
| [Lavavarshney/screenshot-sans-surprise-90](https://github.com/Lavavarshney/screenshot-sans-surprise-90) | ai-built | 89 | dangerous_html:1 |
| [CrooksCodes/StreetWearDemo](https://github.com/CrooksCodes/StreetWearDemo) | ai-stack | 86 | dangerous_html:2 |
| [Sukrittt/fpl-scraper](https://github.com/Sukrittt/fpl-scraper) | ai-stack | 85 | — |
| [YusufBeratZengin/prompt-lint](https://github.com/YusufBeratZengin/prompt-lint) | ai-built | 85 | ci_unpinned_actions:13 |
| [FerQue/shadowq-github-sync](https://github.com/FerQue/shadowq-github-sync) | ai-built | 83 | rls_permissive:2 dangerous_html:1 |
| [abhishekkushwaha30/jaldrishti-dashboard-replica](https://github.com/abhishekkushwaha30/jaldrishti-dashboard-replica) | ai-built | 82 | eval_exec:3 dangerous_html:1 |
| [JoshBong/trace](https://github.com/JoshBong/trace) | ai-built | 74 | math_random_tokens:1 |
| [HashirHanan-MP/desktop-buddies](https://github.com/HashirHanan-MP/desktop-buddies) | ai-built | 72 | math_random_tokens:102 ci_unpinned_actions:5 |
| [ubukhari/agentsmd-lint](https://github.com/ubukhari/agentsmd-lint) | ai-built | 71 | ci_unpinned_actions:3 |
| [ccrngd1/setup-trap](https://github.com/ccrngd1/setup-trap) | ai-built | 68 | — |
| [Othm1ne/appsecradar](https://github.com/Othm1ne/appsecradar) | ai-stack | 65 | sql_concat:3 hardcoded_secret_generic:2 |
| [andieng/quick-time-tracker](https://github.com/andieng/quick-time-tracker) | ai-built | 64 | ci_unpinned_actions:5 rls_permissive:1 |
| [qppd/hydrolyt](https://github.com/qppd/hydrolyt) | ai-stack | 61 | math_random_tokens:3 |
| [kelleyblackmore/Skills](https://github.com/kelleyblackmore/Skills) | ai-built | 57 | — |
| [gabrielvfonseca/rulebook](https://github.com/gabrielvfonseca/rulebook) | ai-built | 56 | ci_unpinned_actions:6 logs_secret_leak:1 |
| [shouryaagrawal1/Nexus](https://github.com/shouryaagrawal1/Nexus) | ai-built | 52 | — |
| [ISUMI-MART/Isumi_mart](https://github.com/ISUMI-MART/Isumi_mart) | ai-built | 50 | — |
| [KareemSultanOfficial/Hirely](https://github.com/KareemSultanOfficial/Hirely) | ai-stack | 49 | — |
| [saurabh-rajput-15/claypull](https://github.com/saurabh-rajput-15/claypull) | ai-built | 46 | ci_unpinned_actions:2 |
| [TempestMK7/photo-puzzles](https://github.com/TempestMK7/photo-puzzles) | ai-built | 45 | math_random_tokens:1 |
| [errordrive/LogMCP](https://github.com/errordrive/LogMCP) | ai-built | 45 | ci_unpinned_actions:4 math_random_tokens:2 |
| [DavidNguyen91/nextjs-todo-app-vercel-supabase](https://github.com/DavidNguyen91/nextjs-todo-app-vercel-supabase) | ai-stack | 44 | math_random_tokens:3 |
| [bcharleson/linkedincli](https://github.com/bcharleson/linkedincli) | ai-built | 41 | math_random_tokens:1 |
| [Saeed-Hussain/Hotel-Management](https://github.com/Saeed-Hussain/Hotel-Management) | ai-stack | 39 | sql_concat:11 |
| [mroqui/raqib](https://github.com/mroqui/raqib) | ai-built | 38 | aws_keys:6 ci_unpinned_actions:4 |
| [hachache/cursorrules](https://github.com/hachache/cursorrules) | ai-built | 37 | — |
| [sholaayodele/explanation-faithfulness-harness](https://github.com/sholaayodele/explanation-faithfulness-harness) | ai-built | 37 | — |
| [KhawarRafique02/taskflow-pro](https://github.com/KhawarRafique02/taskflow-pro) | ai-stack | 35 | supabase_user_metadata:1 |
| [Githubak2002/Tenant-Managment-v2.0](https://github.com/Githubak2002/Tenant-Managment-v2.0) | ai-stack | 34 | — |
| [Saeed-Hussain/thal-university-library](https://github.com/Saeed-Hussain/thal-university-library) | ai-stack | 34 | math_random_tokens:2 service_role_lead:1 |
| [hartforddavis-ai/brass-ai-axioms](https://github.com/hartforddavis-ai/brass-ai-axioms) | ai-built | 34 | — |
| [Sreenivasulu-Kalluru/lighthouse-tracker](https://github.com/Sreenivasulu-Kalluru/lighthouse-tracker) | ai-stack | 33 | — |
| [ronitgupta138/Agent-MemGC](https://github.com/ronitgupta138/Agent-MemGC) | ai-built | 33 | — |
| [ReazGan/sift](https://github.com/ReazGan/sift) | ai-built | 31 | ci_unpinned_actions:4 |
| [TheIntrovertCoder/Promptferry](https://github.com/TheIntrovertCoder/Promptferry) | ai-built | 31 | ci_unpinned_actions:2 |
| [aditytarajmandloi/leaddesk-crm-nextjs](https://github.com/aditytarajmandloi/leaddesk-crm-nextjs) | ai-stack | 31 | — |
| [JonathanWilbur/cursorrules](https://github.com/JonathanWilbur/cursorrules) | ai-built | 30 | — |
| [screenleon/qa-testing-rules](https://github.com/screenleon/qa-testing-rules) | ai-built | 30 | — |
| [Mat34ec/mva-hackathon-2026](https://github.com/Mat34ec/mva-hackathon-2026) | ai-built | 28 | — |
| [SameeulKhondokerJisan/finzyy-ai-assisted-expense-management-system](https://github.com/SameeulKhondokerJisan/finzyy-ai-assisted-expense-management-system) | ai-stack | 28 | — |
| [adamkrawczyk/agentpact-mcp-server](https://github.com/adamkrawczyk/agentpact-mcp-server) | ai-built | 28 | ci_unpinned_actions:5 |
| [cenitu/inventor-mcp-server](https://github.com/cenitu/inventor-mcp-server) | ai-built | 28 | ci_unpinned_actions:2 |
| [mattschaller/agent-context-lint](https://github.com/mattschaller/agent-context-lint) | ai-built | 28 | ci_unpinned_actions:1 |
| [ccrngd1/doc-probe](https://github.com/ccrngd1/doc-probe) | ai-built | 27 | — |
| [furink/CursorRulesSkills](https://github.com/furink/CursorRulesSkills) | ai-built | 27 | — |
| [ShadAhammed/Cursorrules-Shad](https://github.com/ShadAhammed/Cursorrules-Shad) | ai-built | 26 | — |
| [leanmaga/mybalanceapp](https://github.com/leanmaga/mybalanceapp) | ai-stack | 26 | — |
| [vbteja/pm-command-center](https://github.com/vbteja/pm-command-center) | ai-stack | 26 | — |
| [0xelitesystem/agent-rules](https://github.com/0xelitesystem/agent-rules) | ai-built | 24 | ci_unpinned_actions:2 |
| [piecioshka/whose-context-wins](https://github.com/piecioshka/whose-context-wins) | ai-built | 24 | — |
| [bharat3645/agent-rules-audit](https://github.com/bharat3645/agent-rules-audit) | ai-built | 23 | ci_unpinned_actions:5 |
| [rkottomt/research-idea-checker](https://github.com/rkottomt/research-idea-checker) | ai-built | 23 | — |
| [stecymg/ArubaProject](https://github.com/stecymg/ArubaProject) | ai-stack | 23 | — |
| [vatio-ai/example-nextjs-supabase](https://github.com/vatio-ai/example-nextjs-supabase) | ai-stack | 23 | nextpublic_secret_keys:1 |
| [MhmmdFaizal04/cursor-rules-pro](https://github.com/MhmmdFaizal04/cursor-rules-pro) | ai-built | 22 | sql_concat:1 |
| [ehretskyy/drifter](https://github.com/ehretskyy/drifter) | ai-built | 22 | ci_unpinned_actions:2 |
| [sifatshams/nextjs-supabase-starter](https://github.com/sifatshams/nextjs-supabase-starter) | ai-stack | 20 | — |
| [bappelt/anki-hypertts-mcp](https://github.com/bappelt/anki-hypertts-mcp) | ai-built | 19 | ci_unpinned_actions:7 |
| [johndimm/gradual-daylight-saving](https://github.com/johndimm/gradual-daylight-saving) | ai-built | 19 | — |
| [Nihara-D/aegis-cloud-robotics](https://github.com/Nihara-D/aegis-cloud-robotics) | ai-stack | 18 | rls_permissive:2 |
| [MalickDevWeb/skills_wechat_pmt](https://github.com/MalickDevWeb/skills_wechat_pmt) | ai-built | 17 | — |
| [HilalZD/LeakProof](https://github.com/HilalZD/LeakProof) | ai-built | 15 | — |
| [Grace/paladin](https://github.com/Grace/paladin) | ai-built | 14 | ci_unpinned_actions:7 |
| [Usama333-creator/Mashal-olympics](https://github.com/Usama333-creator/Mashal-olympics) | ai-built | 14 | — |
| [analu007/ag-tax-ag-facilita-parceiros](https://github.com/analu007/ag-tax-ag-facilita-parceiros) | ai-built | 14 | — |
| [mnrprojects/Jobz.bar](https://github.com/mnrprojects/Jobz.bar) | ai-built | 14 | — |
| [mycodesweb/carepointhms](https://github.com/mycodesweb/carepointhms) | ai-built | 14 | committed_env:1 env_in_git_history:1 |
| [repiv9-ship-it/out-of-frame](https://github.com/repiv9-ship-it/out-of-frame) | ai-built | 14 | — |
| [wan-projects/belajar-vibe-coding-programmer-zaman-now](https://github.com/wan-projects/belajar-vibe-coding-programmer-zaman-now) | ai-built | 14 | — |
| [BonnieJRobert/context-hub](https://github.com/BonnieJRobert/context-hub) | ai-built | 13 | — |
| [shahanashahana36201-rgb/xyz-cafe](https://github.com/shahanashahana36201-rgb/xyz-cafe) | ai-built | 13 | — |
| [bhanu403/darklens-mcp](https://github.com/bhanu403/darklens-mcp) | ai-built | 12 | — |
| [doomsday-network/web3-agent-skills](https://github.com/doomsday-network/web3-agent-skills) | ai-built | 12 | — |
| [MrSwitch/blockfighter](https://github.com/MrSwitch/blockfighter) | ai-built | 11 | math_random_tokens:19 ci_unpinned_actions:5 |
| [kitforgedev/claude-md-templates](https://github.com/kitforgedev/claude-md-templates) | ai-built | 11 | — |
| [pduggusa/dugganusa-agent-guard](https://github.com/pduggusa/dugganusa-agent-guard) | ai-built | 11 | — |
| [Swastikkkkk/agentdrift](https://github.com/Swastikkkkk/agentdrift) | ai-built | 10 | — |
| [lixingliangsy/contextforge](https://github.com/lixingliangsy/contextforge) | ai-built | 10 | — |
| [younesrest/promptsentry](https://github.com/younesrest/promptsentry) | ai-built | 10 | ci_unpinned_actions:2 |
| [Shokun123/awesome-cursorrules-agent-skills](https://github.com/Shokun123/awesome-cursorrules-agent-skills) | ai-built | 8 | ci_unpinned_actions:3 |
| [jarumgoni/awesome-cursor-rules-2026](https://github.com/jarumgoni/awesome-cursor-rules-2026) | ai-built | 7 | — |
| [amandaballadare/CursorRules](https://github.com/amandaballadare/CursorRules) | ai-built | 6 | — |
| [vishal-kumar9032/agent-context-guard](https://github.com/vishal-kumar9032/agent-context-guard) | ai-built | 6 | — |
| [AymaneWebDEV/developer-prompt-vault](https://github.com/AymaneWebDEV/developer-prompt-vault) | ai-built | 5 | — |
| [edgebuildlabs/evidence-contracts](https://github.com/edgebuildlabs/evidence-contracts) | ai-built | 5 | — |
| [majamil16/cursorrules](https://github.com/majamil16/cursorrules) | ai-built | 5 | — |
| [baby-zack-agent/rules-linter](https://github.com/baby-zack-agent/rules-linter) | ai-built | 4 | — |
| [Kaynetic/gvva-multiverse](https://github.com/Kaynetic/gvva-multiverse) | ai-stack | 3 | — |
| [forbiddenfruit13/cursorrules-test](https://github.com/forbiddenfruit13/cursorrules-test) | ai-built | 3 | — |
| [kulykivska/coderules-generator](https://github.com/kulykivska/coderules-generator) | ai-built | 3 | — |
| [ocalirdigital/nextjs-static-rules](https://github.com/ocalirdigital/nextjs-static-rules) | ai-built | 3 | — |
| [saineelofficial/saineelofficial](https://github.com/saineelofficial/saineelofficial) | ai-built | 3 | ci_unpinned_actions:2 |
| [xiaozhenyangCode/awesome-cursor-rules](https://github.com/xiaozhenyangCode/awesome-cursor-rules) | ai-built | 3 | — |
| [cmartinzip/tokencheat-action](https://github.com/cmartinzip/tokencheat-action) | ai-built | 2 | — |
| [frandevrules/free-nextjs-tailwind-cursorrules](https://github.com/frandevrules/free-nextjs-tailwind-cursorrules) | ai-built | 2 | — |
| [bshx2024/deepseek-v4-1-flash-cursor-claude-code-quickstart](https://github.com/bshx2024/deepseek-v4-1-flash-cursor-claude-code-quickstart) | ai-built | 1 | — |

---

## Calibration Run (سابق المسح — 3 مشاريع، أكتوبر 2026)

> أول تشغيل معايرة على 3 مشاريع (honeypot + clean + NodeGoat) قبل المسح الكامل — البيانات القديمة اتحفظت للأرشيف المنهجي؛ الأرقام المرجعية دلوقتي هي جدول الـ 100 مشروع فوق.
