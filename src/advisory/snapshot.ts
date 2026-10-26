// AUTO-GENERATED from OSV.dev (2026-10) — do not edit by hand.
// Rebuild via scripts/build-advisory-snapshot.mjs (real advisories, bundled per tool release).
// v1.2 policy: npm advisories MODERATE and above, max 60 per package (T14 dependency recall).

export interface Advisory { id: string; aliases?: string[]; severity: string; summary: string; ranges: Array<{ events: Array<Record<string, string>> }>; fixed_hint?: string }

export const SNAPSHOT: { snapshot_date: string; source: string; policy: string; packages: number; advisories: Record<string, Advisory[]>; known_malicious: Record<string, Advisory[]> } = {
  "snapshot_date": "2026-10",
  "source": "OSV.dev (api.osv.dev) — fetched at build time, bundled per tool release for determinism",
  "policy": "npm advisories MODERATE and above (v1.2), ECOSYSTEM/SEMVER ranges, max 60 per package",
  "packages": 21,
  "advisories": {
    "next": [
      {
        "id": "GHSA-2464-fhr4-w9xw",
        "aliases": [],
        "severity": "critical",
        "summary": "Next.js: Unauthenticated Remote Code Execution in Image Optimization API when SVG files are used",
        "ranges": [
          {
            "events": [
              {
                "introduced": "10.0.0"
              },
              {
                "fixed": "15.5.28"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.4.1"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.28"
      },
      {
        "id": "GHSA-2xp9-vwfh-vxw4",
        "aliases": [],
        "severity": "critical",
        "summary": "Next.js: Unauthenticated Remote Code Execution in Image Optimization API when AVIF files are used",
        "ranges": [
          {
            "events": [
              {
                "introduced": "10.0.0"
              },
              {
                "fixed": "15.5.24"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.3.3"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.24"
      },
      {
        "id": "GHSA-673q-mjm6-r5xr",
        "aliases": [],
        "severity": "critical",
        "summary": "Next.js: Unauthenticated Remote Code Execution in `use cache` functions returning typed arrays",
        "ranges": [
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.4.1"
              }
            ]
          }
        ],
        "fixed_hint": "16.4.1"
      },
      {
        "id": "GHSA-9qr9-h5gf-34mp",
        "aliases": [],
        "severity": "critical",
        "summary": "Next.js is vulnerable to RCE in React flight protocol",
        "ranges": [
          {
            "events": [
              {
                "introduced": "14.3.0-canary.77"
              },
              {
                "fixed": "15.0.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.1.0-canary.0"
              },
              {
                "fixed": "15.1.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.2.0-canary.0"
              },
              {
                "fixed": "15.2.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.3.0-canary.0"
              },
              {
                "fixed": "15.3.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.4.0-canary.0"
              },
              {
                "fixed": "15.4.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.5.0-canary.0"
              },
              {
                "fixed": "15.5.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0-canary.0"
              },
              {
                "fixed": "16.0.7"
              }
            ]
          }
        ],
        "fixed_hint": "15.0.5"
      },
      {
        "id": "GHSA-f82v-jwr5-mffw",
        "aliases": [
          "CVE-2025-29927"
        ],
        "severity": "critical",
        "summary": "Authorization Bypass in Next.js Middleware",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "13.5.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "14.0.0"
              },
              {
                "fixed": "14.2.25"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.0.0"
              },
              {
                "fixed": "15.2.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "12.0.0"
              },
              {
                "fixed": "12.3.5"
              }
            ]
          }
        ],
        "fixed_hint": "13.5.9"
      },
      {
        "id": "GHSA-p293-qw3h-jr36",
        "aliases": [
          "CVE-2026-75604"
        ],
        "severity": "critical",
        "summary": "Next.js: Unauthenticated Remote Code Execution on windows-hosted servers",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.4.0"
              },
              {
                "fixed": "15.5.24"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.3.3"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.24"
      },
      {
        "id": "GHSA-vcvr-r3jv-pc5j",
        "aliases": [],
        "severity": "critical",
        "summary": "Next.js: Remote Code Execution in next/og ImageResponse",
        "ranges": [
          {
            "events": [
              {
                "introduced": "16.2.0"
              },
              {
                "fixed": "16.3.6"
              }
            ]
          }
        ],
        "fixed_hint": "16.3.6"
      },
      {
        "id": "GHSA-25mp-g6fv-mqxx",
        "aliases": [
          "CVE-2021-43803"
        ],
        "severity": "high",
        "summary": "Unexpected server crash in Next.js.",
        "ranges": [
          {
            "events": [
              {
                "introduced": "12.0.0"
              },
              {
                "fixed": "12.0.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0.9.9"
              },
              {
                "fixed": "11.1.3"
              }
            ]
          }
        ],
        "fixed_hint": "12.0.5"
      },
      {
        "id": "GHSA-267c-6grr-h53f",
        "aliases": [
          "CVE-2026-44575"
        ],
        "severity": "high",
        "summary": "Next.js has a Middleware / Proxy bypass in App Router applications via segment-prefetch routes",
        "ranges": [
          {
            "events": [
              {
                "introduced": "15.2.0"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-26hh-7cqf-hhc6",
        "aliases": [
          "CVE-2026-45109"
        ],
        "severity": "high",
        "summary": "Next.js has a Middleware / Proxy bypass in App Router applications via segment-prefetch routes - Incomplete Fix Follow-Up",
        "ranges": [
          {
            "events": [
              {
                "introduced": "15.2.0"
              },
              {
                "fixed": "15.5.18"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.6"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.18"
      },
      {
        "id": "GHSA-36qx-fr4f-26g5",
        "aliases": [
          "CVE-2026-44573"
        ],
        "severity": "high",
        "summary": "Next.js has a Middleware / Proxy bypass in Pages Router applications using i18n",
        "ranges": [
          {
            "events": [
              {
                "introduced": "12.2.0"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-3f5c-4qxj-vmpf",
        "aliases": [
          "CVE-2017-16877"
        ],
        "severity": "high",
        "summary": "Next.js Directory Traversal Vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "2.4.1"
              }
            ]
          }
        ],
        "fixed_hint": "2.4.1"
      },
      {
        "id": "GHSA-492v-c6pp-mqqv",
        "aliases": [
          "CVE-2026-44574"
        ],
        "severity": "high",
        "summary": "Next.js has a Middleware / Proxy bypass through dynamic route parameter injection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "15.4.0"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-5j59-xgg2-r9c4",
        "aliases": [],
        "severity": "high",
        "summary": "Next has a Denial of Service with Server Components - Incomplete Fix Follow-Up",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.3.1-canary.0"
              },
              {
                "fixed": "14.2.35"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.0.6"
              },
              {
                "fixed": "15.0.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.1.10"
              },
              {
                "fixed": "15.1.11"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.2.7"
              },
              {
                "fixed": "15.2.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.3.7"
              },
              {
                "fixed": "15.3.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.4.9"
              },
              {
                "fixed": "15.4.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.5.8"
              },
              {
                "fixed": "15.5.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.6.0-canary.59"
              },
              {
                "fixed": "15.6.0-canary.60"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.9"
              },
              {
                "fixed": "16.0.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.1.0-canary.17"
              },
              {
                "fixed": "16.1.0-canary.19"
              }
            ]
          }
        ],
        "fixed_hint": "14.2.35"
      },
      {
        "id": "GHSA-5vj8-3v2h-h38v",
        "aliases": [],
        "severity": "high",
        "summary": "Remote Code Execution in next",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.9.9"
              },
              {
                "fixed": "5.1.0"
              }
            ]
          }
        ],
        "fixed_hint": "5.1.0"
      },
      {
        "id": "GHSA-67rr-84xm-4c7r",
        "aliases": [
          "CVE-2025-49826"
        ],
        "severity": "high",
        "summary": "Next.JS vulnerability can lead to DoS via cache poisoning ",
        "ranges": [
          {
            "events": [
              {
                "introduced": "15.0.4-canary.51"
              },
              {
                "fixed": "15.1.8"
              }
            ]
          }
        ],
        "fixed_hint": "15.1.8"
      },
      {
        "id": "GHSA-6gpp-xcg3-4w24",
        "aliases": [
          "CVE-2026-64642"
        ],
        "severity": "high",
        "summary": "Next.js: Middleware / Proxy bypass in App Router applications using Turbopack and single locale",
        "ranges": [
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.11"
              }
            ]
          }
        ],
        "fixed_hint": "16.2.11"
      },
      {
        "id": "GHSA-77r5-gw3j-2mpf",
        "aliases": [
          "CVE-2024-34350"
        ],
        "severity": "high",
        "summary": "Next.js Vulnerable to HTTP Request Smuggling",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.4.0"
              },
              {
                "fixed": "13.5.1"
              }
            ]
          }
        ],
        "fixed_hint": "13.5.1"
      },
      {
        "id": "GHSA-7gfc-8cq8-jh5f",
        "aliases": [
          "CVE-2024-51479"
        ],
        "severity": "high",
        "summary": "Next.js authorization bypass vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "9.5.5"
              },
              {
                "fixed": "14.2.15"
              }
            ]
          }
        ],
        "fixed_hint": "14.2.15"
      },
      {
        "id": "GHSA-89xv-2m56-2m9x",
        "aliases": [
          "CVE-2026-64649"
        ],
        "severity": "high",
        "summary": "Next.js: Server-Side Request Forgery in Server Actions on custom servers",
        "ranges": [
          {
            "events": [
              {
                "introduced": "14.1.1"
              },
              {
                "fixed": "15.5.21"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.11"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.21"
      },
      {
        "id": "GHSA-8h8q-6873-q5fj",
        "aliases": [],
        "severity": "high",
        "summary": "Next.js Vulnerable to Denial of Service with Server Components",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-9gr3-7897-pp7m",
        "aliases": [
          "CVE-2021-39178"
        ],
        "severity": "high",
        "summary": "XSS in Image Optimization API for Next.js",
        "ranges": [
          {
            "events": [
              {
                "introduced": "10.0.0"
              },
              {
                "fixed": "11.1.1"
              }
            ]
          }
        ],
        "fixed_hint": "11.1.1"
      },
      {
        "id": "GHSA-c4j6-fc7j-m34r",
        "aliases": [
          "CVE-2026-44578"
        ],
        "severity": "high",
        "summary": "Next.js vulnerable to server-side request forgery in applications using WebSocket upgrades",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.4.13"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-cjq9-62q9-8jv4",
        "aliases": [
          "CVE-2026-94483"
        ],
        "severity": "high",
        "summary": "Next.js has Server-Side Request Forgery in Image Optimization",
        "ranges": [
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.3.8"
              }
            ]
          }
        ],
        "fixed_hint": "16.3.8"
      },
      {
        "id": "GHSA-fq54-2j52-jc42",
        "aliases": [
          "CVE-2024-39693"
        ],
        "severity": "high",
        "summary": "Next.js Denial of Service (DoS) condition",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.3.1"
              },
              {
                "fixed": "13.5.0"
              }
            ]
          }
        ],
        "fixed_hint": "13.5.0"
      },
      {
        "id": "GHSA-fr5h-rqp8-mj6g",
        "aliases": [
          "CVE-2024-34351"
        ],
        "severity": "high",
        "summary": "Next.js Server-Side Request Forgery in Server Actions",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.4.0"
              },
              {
                "fixed": "14.1.1"
              }
            ]
          }
        ],
        "fixed_hint": "14.1.1"
      },
      {
        "id": "GHSA-gp8f-8m3g-qvj9",
        "aliases": [
          "CVE-2024-46982"
        ],
        "severity": "high",
        "summary": "Next.js Cache Poisoning",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.5.1"
              },
              {
                "fixed": "13.5.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "14.0.0"
              },
              {
                "fixed": "14.2.10"
              }
            ]
          }
        ],
        "fixed_hint": "13.5.7"
      },
      {
        "id": "GHSA-h25m-26qc-wcjf",
        "aliases": [],
        "severity": "high",
        "summary": "Next.js HTTP request deserialization can lead to DoS when using insecure React Server Components",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "15.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.1.1-canary.0"
              },
              {
                "fixed": "15.1.12"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.2.0-canary.0"
              },
              {
                "fixed": "15.2.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.3.0-canary.0"
              },
              {
                "fixed": "15.3.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.4.0-canary.0"
              },
              {
                "fixed": "15.4.11"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.5.1-canary.0"
              },
              {
                "fixed": "15.5.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.6.0-canary.0"
              },
              {
                "fixed": "15.6.0-canary.61"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0-beta.0"
              },
              {
                "fixed": "16.0.11"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.1.0-canary.0"
              },
              {
                "fixed": "16.1.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.0.8"
      },
      {
        "id": "GHSA-m34x-wgrh-g897",
        "aliases": [
          "CVE-2018-6184"
        ],
        "severity": "high",
        "summary": "Directory traversal vulnerability in Next.js",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "4.2.3"
              }
            ]
          }
        ],
        "fixed_hint": "4.2.3"
      },
      {
        "id": "GHSA-m99w-x7hq-7vfj",
        "aliases": [
          "CVE-2026-64641"
        ],
        "severity": "high",
        "summary": "Next.js: Denial of Service in App Router using Server Actions",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "15.5.21"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.11"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.21"
      },
      {
        "id": "GHSA-mg66-mrh9-m8jx",
        "aliases": [
          "CVE-2026-44579"
        ],
        "severity": "high",
        "summary": "Next.js vulnerable to Denial of Service via connection exhaustion in applications using Cache Components",
        "ranges": [
          {
            "events": [
              {
                "introduced": "15.0.0"
              },
              {
                "fixed": "15.5.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.5"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.16"
      },
      {
        "id": "GHSA-mwv6-3258-q52c",
        "aliases": [],
        "severity": "high",
        "summary": "Next Vulnerable to Denial of Service with Server Components",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.3.0"
              },
              {
                "fixed": "14.2.34"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.0.0-canary.0"
              },
              {
                "fixed": "15.0.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.1.1-canary.0"
              },
              {
                "fixed": "15.1.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.2.0-canary.0"
              },
              {
                "fixed": "15.2.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.3.0-canary.0"
              },
              {
                "fixed": "15.3.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.4.0-canary.0"
              },
              {
                "fixed": "15.4.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.5.1-canary.0"
              },
              {
                "fixed": "15.5.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "15.6.0-canary.0"
              },
              {
                "fixed": "15.6.0-canary.59"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0-beta.0"
              },
              {
                "fixed": "16.0.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.1.0-canary.0"
              },
              {
                "fixed": "16.1.0-canary.17"
              }
            ]
          }
        ],
        "fixed_hint": "14.2.34"
      },
      {
        "id": "GHSA-p3m5-59mp-jv5r",
        "aliases": [
          "CVE-2026-94482"
        ],
        "severity": "high",
        "summary": "Next.js: Denial of Service in App Router using Server Actions",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "15.5.28"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.4.1"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.28"
      },
      {
        "id": "GHSA-p9j2-gv94-2wf4",
        "aliases": [
          "CVE-2026-64645"
        ],
        "severity": "high",
        "summary": "Next.js: Server-Side Request Forgery in rewrites via attacker-controlled destination hostname",
        "ranges": [
          {
            "events": [
              {
                "introduced": "12.0.0"
              },
              {
                "fixed": "15.5.21"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0"
              },
              {
                "fixed": "16.2.11"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.21"
      },
      {
        "id": "GHSA-q4gf-8mx6-v5v3",
        "aliases": [],
        "severity": "high",
        "summary": "Next.js has a Denial of Service with Server Components",
        "ranges": [
          {
            "events": [
              {
                "introduced": "13.0.0"
              },
              {
                "fixed": "15.5.15"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "16.0.0-beta.0"
              },
              {
                "fixed": "16.2.3"
              }
            ]
          }
        ],
        "fixed_hint": "15.5.15"
      }
    ],
    "react": [
      {
        "id": "GHSA-hg79-j56m-fxgv",
        "aliases": [],
        "severity": "high",
        "summary": "Cross-Site Scripting in react",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.0.1"
              },
              {
                "fixed": "0.14.0"
              }
            ]
          }
        ],
        "fixed_hint": "0.14.0"
      }
    ],
    "axios": [
      {
        "id": "GHSA-35jp-ww65-95wh",
        "aliases": [
          "CVE-2026-44494"
        ],
        "severity": "high",
        "summary": "axios Vulnerable to Full Man-in-the-Middle via Prototype Pollution Gadget in `config.proxy`",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-3g43-6gmg-66jw",
        "aliases": [
          "CVE-2026-44495"
        ],
        "severity": "high",
        "summary": "axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.15.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0.19.0"
              },
              {
                "fixed": "0.31.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.15.2"
      },
      {
        "id": "GHSA-3pq3-5fj3-cg6v",
        "aliases": [
          "CVE-2026-101898"
        ],
        "severity": "high",
        "summary": "Axios: HTTP/2 adapter bypasses configured DNS lookup and proxy controls",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.13.0"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-42xw-2xvc-qx8m",
        "aliases": [
          "CVE-2019-10742"
        ],
        "severity": "high",
        "summary": "Denial of Service in axios",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.18.1"
              }
            ]
          }
        ],
        "fixed_hint": "0.18.1"
      },
      {
        "id": "GHSA-43fc-jf86-j433",
        "aliases": [
          "CVE-2026-25639"
        ],
        "severity": "high",
        "summary": "Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.13.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.30.3"
              }
            ]
          }
        ],
        "fixed_hint": "1.13.5"
      },
      {
        "id": "GHSA-4hjh-wcwx-xvwj",
        "aliases": [
          "CVE-2025-58754"
        ],
        "severity": "high",
        "summary": "Axios is vulnerable to DoS attack through lack of data size check",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.12.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0.28.0"
              },
              {
                "fixed": "0.30.2"
              }
            ]
          }
        ],
        "fixed_hint": "1.12.0"
      },
      {
        "id": "GHSA-542g-h47m-68v8",
        "aliases": [
          "CVE-2026-101901"
        ],
        "severity": "high",
        "summary": "Axios: Denial of Service via Unhandled 'error' Event in HTTP/2 ClientHttp2Session Initialization",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.13.0"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-6chq-wfr3-2hj9",
        "aliases": [
          "CVE-2026-42035"
        ],
        "severity": "high",
        "summary": "Axios: Header Injection via Prototype Pollution",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.15.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.31.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.15.1"
      },
      {
        "id": "GHSA-777c-7fjr-54vf",
        "aliases": [
          "CVE-2026-44488"
        ],
        "severity": "high",
        "summary": "Allocation of Resources Without Limits or Throttling in Axios",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.7.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-8hc4-vh64-cxmj",
        "aliases": [
          "CVE-2024-39338"
        ],
        "severity": "high",
        "summary": "Server-Side Request Forgery in axios",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.3.2"
              },
              {
                "fixed": "1.7.4"
              }
            ]
          }
        ],
        "fixed_hint": "1.7.4"
      },
      {
        "id": "GHSA-c29m-xwm3-cm6r",
        "aliases": [
          "CVE-2026-101903"
        ],
        "severity": "high",
        "summary": "Axios: ReDoS in fromDataURI data: URL parser freezes the Node event loop (DoS)",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.16.1"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-cph5-m8f7-6c5x",
        "aliases": [
          "CVE-2021-3749"
        ],
        "severity": "high",
        "summary": "axios Inefficient Regular Expression Complexity vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.21.2"
              }
            ]
          }
        ],
        "fixed_hint": "0.21.2"
      },
      {
        "id": "GHSA-gcfj-64vw-6mp9",
        "aliases": [
          "CVE-2026-67320"
        ],
        "severity": "high",
        "summary": "Axios Node HTTP adapter can use an inherited proxy after interceptor config cloning",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.31.1"
              },
              {
                "fixed": "0.33.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "1.15.2"
              },
              {
                "fixed": "1.18.0"
              }
            ]
          }
        ],
        "fixed_hint": "0.33.0"
      },
      {
        "id": "GHSA-hfxv-24rg-xrqf",
        "aliases": [
          "CVE-2026-44496"
        ],
        "severity": "high",
        "summary": "Axios: Regular Expression Denial of Service (ReDoS) via Cookie Name Injection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.32.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-j5f8-grm9-p9fc",
        "aliases": [
          "CVE-2026-44486"
        ],
        "severity": "high",
        "summary": "Axios: Proxy-Authorization header leaks to redirect target when proxy is re-evaluated to direct connection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.32.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-jr5f-v2jv-69x6",
        "aliases": [
          "CVE-2025-27152"
        ],
        "severity": "high",
        "summary": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.8.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.30.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.8.2"
      },
      {
        "id": "GHSA-m8m8-qj5v-23w3",
        "aliases": [
          "CVE-2026-101905"
        ],
        "severity": "high",
        "summary": "Axios: Node HTTP adapter prototype-pollution gadget allows request socket hijack via inherited createConnection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.15.2"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-mghh-pgcx-3jjj",
        "aliases": [
          "CVE-2026-101906"
        ],
        "severity": "high",
        "summary": "Axios: ReDoS (O(N²)) in shouldBypassProxy host normalization, reachable via untrusted redirect Location",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.15.0"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-p92q-9vqr-4j8v",
        "aliases": [
          "CVE-2026-44487"
        ],
        "severity": "high",
        "summary": "Axios: Proxy-Authorization Credential Leak to Origin Server Across HTTP-to-HTTPS Redirect in Axios Node.js HTTP Adapter",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.32.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-pf86-5x62-jrwf",
        "aliases": [
          "CVE-2026-42033"
        ],
        "severity": "high",
        "summary": "Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, and Request Hijacking",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.15.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.31.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.15.1"
      },
      {
        "id": "GHSA-pjwm-pj3p-43mv",
        "aliases": [
          "CVE-2026-44492"
        ],
        "severity": "high",
        "summary": "axios's shouldBypassProxy does not recognize IPv4-mapped IPv6 addresses, allowing NO_PROXY bypass (incomplete fix for CVE-2025-62718)",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.15.0"
              },
              {
                "fixed": "1.16.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.32.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.16.0"
      },
      {
        "id": "GHSA-pmwg-cvhr-8vh7",
        "aliases": [
          "CVE-2026-42043"
        ],
        "severity": "high",
        "summary": "Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via RFC 1122 Loopback Subnet (127.0.0.0/8) in Axios 1.15.0",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.15.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.31.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.15.1"
      },
      {
        "id": "GHSA-q8qp-cvcw-x6jj",
        "aliases": [
          "CVE-2026-42264"
        ],
        "severity": "high",
        "summary": "Axios has prototype pollution read-side gadgets in HTTP adapter that allow credential injection and request hijacking",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.15.2"
              }
            ]
          }
        ],
        "fixed_hint": "1.15.2"
      },
      {
        "id": "GHSA-r4gj-5m52-g5wh",
        "aliases": [
          "CVE-2026-101907"
        ],
        "severity": "high",
        "summary": "Axios: maxRedirects: 0 is not enforced by the fetch adapter, allowing redirect-based SSRF",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.17.0"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.20.0"
      },
      {
        "id": "GHSA-x97p-jq2g-jp4f",
        "aliases": [
          "CVE-2026-101909"
        ],
        "severity": "high",
        "summary": "Axios: Prototype Pollution Gadget in axios toFormData Options",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.28.0"
              },
              {
                "fixed": "0.34.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "1.15.1"
              },
              {
                "fixed": "1.20.0"
              }
            ]
          }
        ],
        "fixed_hint": "0.34.0"
      }
    ],
    "jsonwebtoken": [
      {
        "id": "GHSA-c7hr-j4mj-j2w6",
        "aliases": [
          "CVE-2015-9235"
        ],
        "severity": "critical",
        "summary": "Verification Bypass in jsonwebtoken",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.2.2"
              }
            ]
          }
        ],
        "fixed_hint": "4.2.2"
      },
      {
        "id": "GHSA-8cf7-32gw-wr33",
        "aliases": [
          "CVE-2022-23539"
        ],
        "severity": "high",
        "summary": "jsonwebtoken unrestricted key type could lead to legacy keys usage ",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "9.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "9.0.0"
      }
    ],
    "node-fetch": [
      {
        "id": "GHSA-r683-j2x4-v87g",
        "aliases": [
          "CVE-2022-0235"
        ],
        "severity": "high",
        "summary": "node-fetch forwards secure headers to untrusted sites",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "3.1.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.6.7"
              }
            ]
          }
        ],
        "fixed_hint": "3.1.1"
      }
    ],
    "semver": [
      {
        "id": "GHSA-c2qf-rxjj-qqgw",
        "aliases": [
          "CVE-2022-25883"
        ],
        "severity": "high",
        "summary": "semver vulnerable to Regular Expression Denial of Service",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.5.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.3.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "2.0.0-alpha"
              },
              {
                "fixed": "5.7.2"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.2"
      },
      {
        "id": "GHSA-x6fg-f45m-jf5q",
        "aliases": [
          "CVE-2015-8855"
        ],
        "severity": "high",
        "summary": "Regular Expression Denial of Service in semver",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.4"
              },
              {
                "fixed": "4.3.2"
              }
            ]
          }
        ],
        "fixed_hint": "4.3.2"
      }
    ],
    "minimist": [
      {
        "id": "GHSA-xvch-5gv4-984h",
        "aliases": [
          "CVE-2021-44906"
        ],
        "severity": "critical",
        "summary": "Prototype Pollution in minimist",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.2.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.2.4"
              }
            ]
          }
        ],
        "fixed_hint": "1.2.6"
      }
    ],
    "lodash": [
      {
        "id": "GHSA-jf85-cpcp-j695",
        "aliases": [
          "CVE-2019-10744",
          "SNYK-JS-LODASH-450202"
        ],
        "severity": "critical",
        "summary": "Prototype Pollution in lodash",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.12"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.14"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.13"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.6.1"
              }
            ]
          }
        ],
        "fixed_hint": "4.17.12"
      },
      {
        "id": "GHSA-35jh-r3h4-6jhm",
        "aliases": [
          "CVE-2021-23337"
        ],
        "severity": "high",
        "summary": "Command Injection in lodash",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.21"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.21"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "4.5.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "1.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "4.17.21"
      },
      {
        "id": "GHSA-4xc9-xhrj-v574",
        "aliases": [
          "CVE-2018-16487"
        ],
        "severity": "high",
        "summary": "Prototype Pollution in lodash",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.17.11"
              }
            ]
          }
        ],
        "fixed_hint": "4.17.11"
      },
      {
        "id": "GHSA-p6mc-m468-83gw",
        "aliases": [
          "CVE-2020-8203"
        ],
        "severity": "high",
        "summary": "Prototype Pollution in lodash",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.7.0"
              },
              {
                "fixed": "4.17.19"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "3.7.0"
              },
              {
                "fixed": "4.17.20"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "last_affected": "4.4.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "3.7.0"
              },
              {
                "last_affected": "4.3.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "4.3.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "4.10.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "4.10.2"
              }
            ]
          }
        ],
        "fixed_hint": "4.17.19"
      },
      {
        "id": "GHSA-r5fr-rjxr-66jc",
        "aliases": [
          "CVE-2026-4800"
        ],
        "severity": "high",
        "summary": "lodash vulnerable to Code Injection via `_.template` imports key names",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.18.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.18.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.18.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.18.0"
              }
            ]
          }
        ],
        "fixed_hint": "4.18.0"
      }
    ],
    "ws": [
      {
        "id": "GHSA-3h5v-q93c-6h6q",
        "aliases": [
          "CVE-2024-37890"
        ],
        "severity": "high",
        "summary": "ws affected by a DoS when handling a request with many HTTP headers",
        "ranges": [
          {
            "events": [
              {
                "introduced": "2.1.0"
              },
              {
                "fixed": "5.2.4"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.2.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.5.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.17.1"
              }
            ]
          }
        ],
        "fixed_hint": "5.2.4"
      },
      {
        "id": "GHSA-5v72-xg48-5rpm",
        "aliases": [],
        "severity": "high",
        "summary": "Denial of Service in ws",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.6.0"
              },
              {
                "fixed": "1.1.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "2.0.0"
              },
              {
                "fixed": "3.3.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.1.5"
      },
      {
        "id": "GHSA-6663-c963-2gqg",
        "aliases": [
          "CVE-2016-10542"
        ],
        "severity": "high",
        "summary": "DoS due to excessively large websocket message in ws",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "1.1.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.1.1"
      },
      {
        "id": "GHSA-96hv-2xvq-fx4p",
        "aliases": [
          "CVE-2026-48779"
        ],
        "severity": "high",
        "summary": "ws: Memory exhaustion DoS from tiny fragments and data chunks",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.1.0"
              },
              {
                "fixed": "5.2.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.2.4"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.5.11"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.21.0"
              }
            ]
          }
        ],
        "fixed_hint": "5.2.5"
      }
    ],
    "undici": [
      {
        "id": "GHSA-38rv-x7px-6hhq",
        "aliases": [
          "CVE-2026-9675"
        ],
        "severity": "high",
        "summary": "undici WebSocket client vulnerable to denial of service via cumulative fragment bypass",
        "ranges": [
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.5.0"
              }
            ]
          }
        ],
        "fixed_hint": "8.5.0"
      },
      {
        "id": "GHSA-4cwx-7wf7-3272",
        "aliases": [
          "CVE-2026-13697"
        ],
        "severity": "high",
        "summary": "undici vulnerable to cross-user information disclosure and parse-time crash via degenerate private cache directives",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.29.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.9.0"
              }
            ]
          }
        ],
        "fixed_hint": "7.29.0"
      },
      {
        "id": "GHSA-f269-vfmq-vjvj",
        "aliases": [
          "CVE-2026-1528"
        ],
        "severity": "high",
        "summary": "Undici: Malicious WebSocket 64-bit length overflows parser and crashes the client",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.24.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.24.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.24.0"
      },
      {
        "id": "GHSA-hm92-r4w5-c3mj",
        "aliases": [
          "CVE-2026-6734"
        ],
        "severity": "high",
        "summary": "undici vulnerable to cross-origin request routing via SOCKS5 proxy pool reuse",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.23.0"
              },
              {
                "fixed": "7.28.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.2.0"
              }
            ]
          }
        ],
        "fixed_hint": "7.28.0"
      },
      {
        "id": "GHSA-pgw7-wx7w-2w33",
        "aliases": [
          "CVE-2022-32210"
        ],
        "severity": "high",
        "summary": "ProxyAgent vulnerable to MITM",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.8.2"
              },
              {
                "fixed": "5.5.1"
              }
            ]
          }
        ],
        "fixed_hint": "5.5.1"
      },
      {
        "id": "GHSA-r6ch-mqf9-qc9w",
        "aliases": [
          "CVE-2023-24807"
        ],
        "severity": "high",
        "summary": "Regular Expression Denial of Service in Headers",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "5.19.1"
              }
            ]
          }
        ],
        "fixed_hint": "5.19.1"
      },
      {
        "id": "GHSA-rfgv-xxqx-mfg5",
        "aliases": [
          "CVE-2026-19534"
        ],
        "severity": "high",
        "summary": "undici vulnerable to Denial of Service via unrequested WebSocket subprotocol",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.7.0"
              },
              {
                "fixed": "6.28.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.29.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.10.2"
              }
            ]
          }
        ],
        "fixed_hint": "6.28.1"
      },
      {
        "id": "GHSA-v9p9-hfj2-hcw8",
        "aliases": [
          "CVE-2026-2229"
        ],
        "severity": "high",
        "summary": "Undici has Unhandled Exception in WebSocket Client Due to Invalid server_max_window_bits Validation",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.24.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.24.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.24.0"
      },
      {
        "id": "GHSA-vmh5-mc38-953g",
        "aliases": [
          "CVE-2026-9697"
        ],
        "severity": "high",
        "summary": "undici vulnerable to TLS certificate validation bypass via dropped requestTls in SOCKS5 ProxyAgent",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.23.0"
              },
              {
                "fixed": "7.28.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.5.0"
              }
            ]
          }
        ],
        "fixed_hint": "7.28.0"
      },
      {
        "id": "GHSA-vp8m-p9jh-q5pm",
        "aliases": [
          "CVE-2026-85152"
        ],
        "severity": "high",
        "summary": "undici vulnerable to cross-origin cache poisoning via missing origin isolation in interceptors",
        "ranges": [
          {
            "events": [
              {
                "introduced": "8.10.0"
              },
              {
                "fixed": "8.10.2"
              }
            ]
          }
        ],
        "fixed_hint": "8.10.2"
      },
      {
        "id": "GHSA-vrm6-8vpv-qv8q",
        "aliases": [
          "CVE-2026-1526"
        ],
        "severity": "high",
        "summary": "Undici has Unbounded Memory Consumption in WebSocket permessage-deflate Decompression",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.24.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.24.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.24.0"
      },
      {
        "id": "GHSA-vxpw-j846-p89q",
        "aliases": [
          "CVE-2026-12151"
        ],
        "severity": "high",
        "summary": "undici WebSocket client vulnerable to denial of service via fragment count bypass",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.27.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.28.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.5.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.27.0"
      },
      {
        "id": "GHSA-w293-vg96-wgc3",
        "aliases": [
          "CVE-2026-84961"
        ],
        "severity": "high",
        "summary": "undici vulnerable to TLS certificate validation bypass via dropped connect options in BalancedPool",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.24.1"
              },
              {
                "fixed": "7.29.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.10.2"
              }
            ]
          }
        ],
        "fixed_hint": "7.29.1"
      },
      {
        "id": "GHSA-xjj6-f33q-929c",
        "aliases": [
          "CVE-2026-109869"
        ],
        "severity": "high",
        "summary": "undici vulnerable to Denial of Service via unhandled error on excessive content-encodings",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.23.0"
              },
              {
                "fixed": "6.29.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.18.0"
              },
              {
                "fixed": "7.30.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.12.2"
              }
            ]
          }
        ],
        "fixed_hint": "6.29.1"
      }
    ],
    "tar": [
      {
        "id": "GHSA-23hp-3jrh-7fpw",
        "aliases": [
          "CVE-2026-59873"
        ],
        "severity": "critical",
        "summary": "node-tar: Decompression/parse DoS via unlimited input",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.19"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.19"
      },
      {
        "id": "GHSA-34x7-hfp2-rc4v",
        "aliases": [
          "CVE-2026-24842"
        ],
        "severity": "high",
        "summary": "node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.7"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.7"
      },
      {
        "id": "GHSA-3jfq-g458-7qm9",
        "aliases": [
          "CVE-2021-32804"
        ],
        "severity": "high",
        "summary": "Arbitrary File Creation/Overwrite due to insufficient absolute path sanitization",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.2.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.4.14"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.0.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.1.1"
              }
            ]
          }
        ],
        "fixed_hint": "3.2.2"
      },
      {
        "id": "GHSA-5955-9wpr-37jh",
        "aliases": [
          "CVE-2021-37713"
        ],
        "severity": "high",
        "summary": "Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.4.18"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.0.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.1.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.18"
      },
      {
        "id": "GHSA-83g3-92jg-28cx",
        "aliases": [
          "CVE-2026-26960"
        ],
        "severity": "high",
        "summary": "Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.8"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.8"
      },
      {
        "id": "GHSA-8qq5-rm4j-mr97",
        "aliases": [
          "CVE-2026-23745"
        ],
        "severity": "high",
        "summary": "node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.3"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.3"
      },
      {
        "id": "GHSA-8x88-c5mf-7j5w",
        "aliases": [
          "CVE-2026-59874"
        ],
        "severity": "high",
        "summary": "node-tar: Negative tar entry size causes infinite loop in archive replace",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.18"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.18"
      },
      {
        "id": "GHSA-9ppj-qmqm-q256",
        "aliases": [
          "CVE-2026-31802"
        ],
        "severity": "high",
        "summary": "node-tar Symlink Path Traversal via Drive-Relative Linkpath",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.11"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.11"
      },
      {
        "id": "GHSA-9r2w-394v-53qc",
        "aliases": [
          "CVE-2021-37701"
        ],
        "severity": "high",
        "summary": "Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning using symbolic links",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "4.4.16"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.1.7"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.16"
      },
      {
        "id": "GHSA-gfjr-3jmm-4g9v",
        "aliases": [
          "CVE-2015-8860"
        ],
        "severity": "high",
        "summary": "Symlink Arbitrary File Overwrite in tar",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "2.0.0"
      },
      {
        "id": "GHSA-j44m-qm6p-hp7m",
        "aliases": [
          "CVE-2018-20834"
        ],
        "severity": "high",
        "summary": "Arbitrary File Overwrite in tar",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "4.4.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.2.2"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.2"
      },
      {
        "id": "GHSA-qffp-2rhf-9h96",
        "aliases": [
          "CVE-2026-29786"
        ],
        "severity": "high",
        "summary": "tar has Hardlink Path Traversal via Drive-Relative Linkpath",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.10"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.10"
      },
      {
        "id": "GHSA-qq89-hq3f-393p",
        "aliases": [
          "CVE-2021-37712"
        ],
        "severity": "high",
        "summary": "Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning using symbolic links",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "4.4.18"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.0.10"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.1.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.18"
      },
      {
        "id": "GHSA-r292-9mhp-454m",
        "aliases": [
          "CVE-2026-73566"
        ],
        "severity": "high",
        "summary": "node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar with member selection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.21"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.21"
      },
      {
        "id": "GHSA-r628-mhmh-qjhw",
        "aliases": [
          "CVE-2021-32803"
        ],
        "severity": "high",
        "summary": "Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "3.2.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.4.15"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.0.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.1.2"
              }
            ]
          }
        ],
        "fixed_hint": "3.2.3"
      },
      {
        "id": "GHSA-r6q2-hw4h-h46w",
        "aliases": [
          "CVE-2026-23950"
        ],
        "severity": "high",
        "summary": "Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.5.4"
              }
            ]
          }
        ],
        "fixed_hint": "7.5.4"
      }
    ],
    "shell-quote": [
      {
        "id": "GHSA-g4rg-993r-mgx7",
        "aliases": [
          "CVE-2021-42740"
        ],
        "severity": "critical",
        "summary": "Improper Neutralization of Special Elements used in a Command in Shell-quote",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.6.3"
              },
              {
                "fixed": "1.7.3"
              }
            ]
          }
        ],
        "fixed_hint": "1.7.3"
      },
      {
        "id": "GHSA-pqg4-j6r4-53mv",
        "aliases": [
          "CVE-2026-102422"
        ],
        "severity": "critical",
        "summary": "shell-quote: `quote()` command injection via a line terminator in a token after a `{ comment }` token",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.8.4"
              },
              {
                "fixed": "1.11.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.11.0"
      },
      {
        "id": "GHSA-qg8p-v9q4-gh34",
        "aliases": [
          "CVE-2016-10541"
        ],
        "severity": "critical",
        "summary": "Potential Command Injection in shell-quote",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "1.6.1"
              }
            ]
          }
        ],
        "fixed_hint": "1.6.1"
      },
      {
        "id": "GHSA-w7jw-789q-3m8p",
        "aliases": [
          "CVE-2026-9277"
        ],
        "severity": "critical",
        "summary": "shell-quote quote() does not escape newlines in object .op values",
        "ranges": [
          {
            "events": [
              {
                "introduced": "1.1.0"
              },
              {
                "fixed": "1.8.4"
              }
            ]
          }
        ],
        "fixed_hint": "1.8.4"
      },
      {
        "id": "GHSA-395f-4hp3-45gv",
        "aliases": [
          "CVE-2026-13311"
        ],
        "severity": "high",
        "summary": "shell-quote: Quadratic-complexity Denial of Service in `parse()` (CWE-407)",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "1.9.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.9.0"
      }
    ],
    "socket.io": [
      {
        "id": "GHSA-qv2v-m59f-v5fw",
        "aliases": [
          "CVE-2017-16031"
        ],
        "severity": "high",
        "summary": "Insecure randomness in socket.io",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.9.7"
              }
            ]
          }
        ],
        "fixed_hint": "0.9.7"
      }
    ],
    "zod": [
      {
        "id": "GHSA-mrhx-c7xc-m3w5",
        "aliases": [
          "CVE-2023-54404"
        ],
        "severity": "high",
        "summary": "Zod can exhaust memory while validating oversized constrained collections",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.6.6"
              }
            ]
          }
        ],
        "fixed_hint": "4.6.6"
      }
    ],
    "typeorm": [
      {
        "id": "GHSA-fx4w-v43j-vc45",
        "aliases": [
          "CVE-2022-33171"
        ],
        "severity": "critical",
        "summary": "SQL injection in typeORM",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.3.0"
              }
            ]
          }
        ],
        "fixed_hint": "0.3.0"
      },
      {
        "id": "GHSA-pf2j-9qmp-jqr2",
        "aliases": [
          "CVE-2020-8158"
        ],
        "severity": "critical",
        "summary": "TypeORM vulnerable to MAID and Prototype Pollution",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.2.25"
              }
            ]
          }
        ],
        "fixed_hint": "0.2.25"
      },
      {
        "id": "GHSA-w7q7-vjp8-7jv4",
        "aliases": [],
        "severity": "critical",
        "summary": "SQL Injection in typeorm",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.1.15"
              }
            ]
          }
        ],
        "fixed_hint": "0.1.15"
      },
      {
        "id": "GHSA-q2pj-6v73-8rgj",
        "aliases": [
          "CVE-2025-60542"
        ],
        "severity": "high",
        "summary": "TypeORM vulnerable to SQL injection via crafted request to repository.save or repository.update",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.3.26"
              }
            ]
          }
        ],
        "fixed_hint": "0.3.26"
      }
    ],
    "mongoose": [
      {
        "id": "GHSA-8687-vv9j-hgph",
        "aliases": [
          "CVE-2019-17426"
        ],
        "severity": "critical",
        "summary": "Improper Input Validation in Automattic Mongoose",
        "ranges": [
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "5.7.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.13.21"
              }
            ]
          }
        ],
        "fixed_hint": "5.7.5"
      },
      {
        "id": "GHSA-9m93-w8w6-76hh",
        "aliases": [
          "BIT-mongoose-2023-3696",
          "CVE-2023-3696"
        ],
        "severity": "critical",
        "summary": "Mongoose Prototype Pollution vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.3.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.11.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "5.13.20"
              }
            ]
          }
        ],
        "fixed_hint": "7.3.3"
      },
      {
        "id": "GHSA-h8hf-x3f4-xwgp",
        "aliases": [
          "CVE-2022-24304"
        ],
        "severity": "critical",
        "summary": "Mongoose Vulnerable to Prototype Pollution in Schema Object",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.4.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "5.13.15"
              }
            ]
          }
        ],
        "fixed_hint": "6.4.6"
      },
      {
        "id": "GHSA-vg7j-7cwx-8wgw",
        "aliases": [
          "BIT-mongoose-2025-23061",
          "CVE-2025-23061"
        ],
        "severity": "critical",
        "summary": "Mongoose search injection vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "8.0.0-rc0"
              },
              {
                "fixed": "8.9.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0-rc0"
              },
              {
                "fixed": "7.8.4"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.13.6"
              }
            ]
          }
        ],
        "fixed_hint": "8.9.5"
      },
      {
        "id": "GHSA-f825-f98c-gj3g",
        "aliases": [
          "BIT-mongoose-2022-2564",
          "CVE-2022-2564"
        ],
        "severity": "high",
        "summary": "automattic/mongoose vulnerable to Prototype pollution via Schema.path",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.4.6"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "5.13.15"
              }
            ]
          }
        ],
        "fixed_hint": "6.4.6"
      },
      {
        "id": "GHSA-m7xq-9374-9rvx",
        "aliases": [
          "BIT-mongoose-2024-53900",
          "CVE-2024-53900"
        ],
        "severity": "high",
        "summary": "Mongoose search injection vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "8.0.0-rc0"
              },
              {
                "fixed": "8.8.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0-rc0"
              },
              {
                "fixed": "7.8.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.0.0-rc0"
              },
              {
                "fixed": "6.13.5"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "3.6.0-rc0"
              },
              {
                "fixed": "5.13.23"
              }
            ]
          }
        ],
        "fixed_hint": "8.8.3"
      },
      {
        "id": "GHSA-wpg9-53fq-2r8h",
        "aliases": [
          "BIT-mongoose-2026-42334",
          "CVE-2026-42334"
        ],
        "severity": "high",
        "summary": "Mongoose's Improper Sanitization of $nor in sanitizeFilter May Allow NoSQL Injection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.13.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "7.0.0"
              },
              {
                "fixed": "7.8.9"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "8.0.0"
              },
              {
                "fixed": "8.22.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "9.0.0"
              },
              {
                "fixed": "9.1.6"
              }
            ]
          }
        ],
        "fixed_hint": "6.13.9"
      }
    ],
    "express": [
      {
        "id": "GHSA-cm5g-3pgc-8rg4",
        "aliases": [
          "CVE-2024-10491"
        ],
        "severity": "moderate",
        "summary": "Express ressource injection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.0.0-rc1"
              }
            ]
          }
        ],
        "fixed_hint": "4.0.0-rc1"
      },
      {
        "id": "GHSA-gpvr-g6gh-9mc2",
        "aliases": [
          "CVE-2014-6393"
        ],
        "severity": "moderate",
        "summary": "No Charset in Content-Type Header in express",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.11.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.5.0"
              }
            ]
          }
        ],
        "fixed_hint": "3.11.0"
      },
      {
        "id": "GHSA-rv95-896h-c2vc",
        "aliases": [
          "CVE-2024-29041"
        ],
        "severity": "moderate",
        "summary": "Express.js Open Redirect in malformed URLs",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.19.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "5.0.0-alpha.1"
              },
              {
                "fixed": "5.0.0-beta.3"
              }
            ]
          }
        ],
        "fixed_hint": "4.19.2"
      }
    ],
    "handlebars": [
      {
        "id": "GHSA-2w6w-674q-4c4q",
        "aliases": [
          "CVE-2026-33937"
        ],
        "severity": "critical",
        "summary": "Handlebars.js has JavaScript Injection via AST Type Confusion",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-765h-qjxv-5f44",
        "aliases": [
          "CVE-2021-23383"
        ],
        "severity": "critical",
        "summary": "Prototype Pollution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.7.7"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.7"
      },
      {
        "id": "GHSA-8r5x-fm3f-whwj",
        "aliases": [
          "CVE-2026-106446"
        ],
        "severity": "critical",
        "summary": "Handlebars: JavaScript Injection via AST Type Confusion in compile (bypass of CVE-2026-33937)",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.10"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.10"
      },
      {
        "id": "GHSA-f2jv-r9rf-7988",
        "aliases": [
          "CVE-2021-23369"
        ],
        "severity": "critical",
        "summary": "Remote code execution in handlebars when compiling templates",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.7.7"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.7"
      },
      {
        "id": "GHSA-p8wg-vrv2-v86f",
        "aliases": [
          "CVE-2026-106445"
        ],
        "severity": "critical",
        "summary": "Handlebars: JavaScript Injection via Own Property Check Bypass",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.0.0"
              },
              {
                "fixed": "4.7.10"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.10"
      },
      {
        "id": "GHSA-w457-6q6x-cgp9",
        "aliases": [
          "CVE-2019-19919"
        ],
        "severity": "critical",
        "summary": "Prototype Pollution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.3.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.8"
              }
            ]
          }
        ],
        "fixed_hint": "4.3.0"
      },
      {
        "id": "GHSA-2cf5-4w76-r9qv",
        "aliases": [],
        "severity": "high",
        "summary": "Arbitrary Code Execution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.5.2"
              }
            ]
          }
        ],
        "fixed_hint": "3.0.8"
      },
      {
        "id": "GHSA-3cqr-58rm-57f8",
        "aliases": [
          "CVE-2019-20920"
        ],
        "severity": "high",
        "summary": "Arbitrary Code Execution in Handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.5.3"
              }
            ]
          }
        ],
        "fixed_hint": "3.0.8"
      },
      {
        "id": "GHSA-3mfm-83xf-c92r",
        "aliases": [
          "CVE-2026-33938"
        ],
        "severity": "high",
        "summary": "Handlebars.js has JavaScript Injection via AST Type Confusion by tampering @partial-block",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-62gr-4qp9-h98f",
        "aliases": [
          "CVE-2019-20922"
        ],
        "severity": "high",
        "summary": "Regular Expression Denial of Service in Handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.4.5"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.5"
      },
      {
        "id": "GHSA-9cx6-37pm-9jff",
        "aliases": [
          "CVE-2026-33939"
        ],
        "severity": "high",
        "summary": "Handlebars.js has Denial of Service via Malformed Decorator Syntax in Template Compilation",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-g9r4-xpmj-mj65",
        "aliases": [],
        "severity": "high",
        "summary": "Prototype Pollution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.5.3"
              }
            ]
          }
        ],
        "fixed_hint": "3.0.8"
      },
      {
        "id": "GHSA-q2c6-c6pm-g3gh",
        "aliases": [],
        "severity": "high",
        "summary": "Arbitrary Code Execution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.8"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.5.3"
              }
            ]
          }
        ],
        "fixed_hint": "3.0.8"
      },
      {
        "id": "GHSA-q42p-pg8m-cqh6",
        "aliases": [],
        "severity": "high",
        "summary": "Prototype Pollution in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.1.0"
              },
              {
                "fixed": "4.1.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.0.14"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.0.7"
              }
            ]
          }
        ],
        "fixed_hint": "4.1.2"
      },
      {
        "id": "GHSA-xhpv-hc6g-r9c6",
        "aliases": [
          "CVE-2026-33940"
        ],
        "severity": "high",
        "summary": "Handlebars.js has JavaScript Injection via AST Type Confusion when passing an object as dynamic partial",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-xjpj-3mr7-gcpf",
        "aliases": [
          "CVE-2026-33941"
        ],
        "severity": "high",
        "summary": "Handlebars.js has JavaScript Injection in CLI Precompiler via Unescaped Names and Options",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-2qvq-rjwj-gvw9",
        "aliases": [
          "CVE-2026-33916"
        ],
        "severity": "moderate",
        "summary": "Handlebars.js has Prototype Pollution Leading to XSS through Partial Template Injection",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-7rx3-28cr-v5wh",
        "aliases": [],
        "severity": "moderate",
        "summary": "Handlebars.js has a Prototype Method Access Control Gap via Missing __lookupSetter__ Blocklist Entry",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.6.0"
              },
              {
                "fixed": "4.7.9"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.9"
      },
      {
        "id": "GHSA-9prh-257w-9277",
        "aliases": [
          "CVE-2015-8861"
        ],
        "severity": "moderate",
        "summary": "Cross-Site Scripting in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "4.0.0"
      },
      {
        "id": "GHSA-f52g-6jhx-586p",
        "aliases": [],
        "severity": "moderate",
        "summary": "Denial of Service in handlebars",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.4.5"
              }
            ]
          }
        ],
        "fixed_hint": "4.4.5"
      },
      {
        "id": "GHSA-xw65-4hp5-5hc7",
        "aliases": [
          "CVE-2026-106444"
        ],
        "severity": "moderate",
        "summary": "Handlebars: JavaScript Injection via Unsafe Inline Embedding of Precompiled Templates",
        "ranges": [
          {
            "events": [
              {
                "introduced": "4.0.0"
              },
              {
                "fixed": "4.7.10"
              }
            ]
          }
        ],
        "fixed_hint": "4.7.10"
      }
    ],
    "moment": [
      {
        "id": "GHSA-446m-mv8f-q348",
        "aliases": [
          "CVE-2017-18214"
        ],
        "severity": "high",
        "summary": "Regular Expression Denial of Service in moment",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.19.3"
              }
            ]
          }
        ],
        "fixed_hint": "2.19.3"
      },
      {
        "id": "GHSA-8hfj-j24r-96c4",
        "aliases": [
          "CVE-2022-24785"
        ],
        "severity": "high",
        "summary": "Path Traversal: 'dir/../../filename' in moment.locale",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.29.2"
              }
            ]
          }
        ],
        "fixed_hint": "2.29.2"
      },
      {
        "id": "GHSA-wc69-rhjr-hc9g",
        "aliases": [
          "CVE-2022-31129"
        ],
        "severity": "high",
        "summary": "Moment.js vulnerable to Inefficient Regular Expression Complexity",
        "ranges": [
          {
            "events": [
              {
                "introduced": "2.18.0"
              },
              {
                "fixed": "2.29.4"
              }
            ]
          }
        ],
        "fixed_hint": "2.29.4"
      },
      {
        "id": "GHSA-4p3w-j4w9-5jqw",
        "aliases": [
          "CVE-2026-17495"
        ],
        "severity": "moderate",
        "summary": "moment vulnerable to Path Traversal via crafted non-string locale name",
        "ranges": [
          {
            "events": [
              {
                "introduced": "2.29.2"
              },
              {
                "fixed": "2.31.0"
              }
            ]
          }
        ],
        "fixed_hint": "2.31.0"
      },
      {
        "id": "GHSA-87vv-r9j6-g5qv",
        "aliases": [
          "CVE-2016-4055"
        ],
        "severity": "moderate",
        "summary": "Regular Expression Denial of Service in moment",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.11.2"
              }
            ]
          }
        ],
        "fixed_hint": "2.11.2"
      }
    ],
    "qs": [
      {
        "id": "GHSA-f9cm-p3w6-xvr3",
        "aliases": [
          "CVE-2014-10064"
        ],
        "severity": "high",
        "summary": "Denial-of-Service Extended Event Loop Blocking in qs",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "1.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.0.0"
      },
      {
        "id": "GHSA-gqgv-6jq5-jjj9",
        "aliases": [
          "CVE-2017-1000048"
        ],
        "severity": "high",
        "summary": "Prototype Pollution Protection Bypass in qs",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.0.4"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.1.0"
              },
              {
                "fixed": "6.1.2"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.2.0"
              },
              {
                "fixed": "6.2.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.3.0"
              },
              {
                "fixed": "6.3.2"
              }
            ]
          }
        ],
        "fixed_hint": "6.0.4"
      },
      {
        "id": "GHSA-hrpp-h998-j3pp",
        "aliases": [
          "CVE-2022-24999"
        ],
        "severity": "high",
        "summary": "qs vulnerable to Prototype Pollution",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.10.0"
              },
              {
                "fixed": "6.10.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.9.0"
              },
              {
                "fixed": "6.9.7"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.8.0"
              },
              {
                "fixed": "6.8.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.7.0"
              },
              {
                "fixed": "6.7.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.6.0"
              },
              {
                "fixed": "6.6.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.5.0"
              },
              {
                "fixed": "6.5.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.4.0"
              },
              {
                "fixed": "6.4.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "6.3.0"
              },
              {
                "fixed": "6.3.3"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.2.4"
              }
            ]
          }
        ],
        "fixed_hint": "6.10.3"
      },
      {
        "id": "GHSA-jjv7-qpx3-h62q",
        "aliases": [
          "CVE-2014-7191"
        ],
        "severity": "high",
        "summary": "Denial-of-Service Memory Exhaustion in qs",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "1.0.0"
              }
            ]
          }
        ],
        "fixed_hint": "1.0.0"
      },
      {
        "id": "GHSA-4mjr-xmp4-gh2g",
        "aliases": [
          "CVE-2026-82417"
        ],
        "severity": "moderate",
        "summary": "qs: Denial of Service via Attacker Controlled isBuffer",
        "ranges": [
          {
            "events": [
              {
                "introduced": "2.2.5"
              },
              {
                "fixed": "6.16.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.16.0"
      },
      {
        "id": "GHSA-6rw7-vpxm-498p",
        "aliases": [
          "CVE-2025-15284"
        ],
        "severity": "moderate",
        "summary": "qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "6.14.1"
              }
            ]
          }
        ],
        "fixed_hint": "6.14.1"
      },
      {
        "id": "GHSA-q8mj-m7cp-5q26",
        "aliases": [
          "CVE-2026-8723"
        ],
        "severity": "moderate",
        "summary": "qs has a remotely triggerable DoS: qs.stringify crashes with TypeError on null/undefined entries in comma-format arrays when encodeValuesOnly is set",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.11.1"
              },
              {
                "fixed": "6.15.2"
              }
            ]
          }
        ],
        "fixed_hint": "6.15.2"
      },
      {
        "id": "GHSA-x5fp-wj9c-mxmx",
        "aliases": [
          "CVE-2026-82562"
        ],
        "severity": "moderate",
        "summary": "qs array-limit bypass via bracket-key comma parsing",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.14.2"
              },
              {
                "fixed": "6.16.0"
              }
            ]
          }
        ],
        "fixed_hint": "6.16.0"
      }
    ],
    "serialize-javascript": [
      {
        "id": "GHSA-5c6j-r48x-rmvq",
        "aliases": [],
        "severity": "high",
        "summary": "Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "7.0.3"
              }
            ]
          }
        ],
        "fixed_hint": "7.0.3"
      },
      {
        "id": "GHSA-hxcc-f52p-wc94",
        "aliases": [
          "CVE-2020-7660"
        ],
        "severity": "high",
        "summary": "Insecure serialization leading to RCE in serialize-javascript",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "3.1.0"
              }
            ]
          }
        ],
        "fixed_hint": "3.1.0"
      },
      {
        "id": "GHSA-76p7-773f-r4q5",
        "aliases": [
          "CVE-2024-11831"
        ],
        "severity": "moderate",
        "summary": "Cross-site Scripting (XSS) in serialize-javascript",
        "ranges": [
          {
            "events": [
              {
                "introduced": "6.0.0"
              },
              {
                "fixed": "6.0.2"
              }
            ]
          }
        ],
        "fixed_hint": "6.0.2"
      },
      {
        "id": "GHSA-h9rv-jmmf-4pgx",
        "aliases": [
          "CVE-2019-16769"
        ],
        "severity": "moderate",
        "summary": "Cross-Site Scripting in serialize-javascript",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.1.1"
              }
            ]
          }
        ],
        "fixed_hint": "2.1.1"
      },
      {
        "id": "GHSA-qj8w-gfj5-8c6v",
        "aliases": [
          "CVE-2026-34043"
        ],
        "severity": "moderate",
        "summary": "Serialize JavaScript has CPU Exhaustion Denial of Service via crafted array-like objects",
        "ranges": [
          {
            "events": [
              {
                "introduced": "5.0.0"
              },
              {
                "fixed": "7.0.5"
              }
            ]
          }
        ],
        "fixed_hint": "7.0.5"
      }
    ]
  },
  "known_malicious": {
    "crossenv": [
      {
        "id": "GHSA-c2m4-w5hm-vqjw",
        "severity": "high",
        "summary": "crossenv is malware",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "last_affected": "1.0.1"
              }
            ]
          }
        ]
      }
    ],
    "event-stream": [
      {
        "id": "GHSA-mh6f-8j2x-4483",
        "severity": "critical",
        "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
        "ranges": [
          {
            "events": [
              {
                "introduced": "3.3.6"
              },
              {
                "fixed": "4.0.0"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0"
              }
            ]
          }
        ]
      }
    ],
    "node-ipc": [
      {
        "id": "GHSA-3mpp-xfvh-qh37",
        "severity": "high",
        "summary": "node-ipc behavior change",
        "ranges": [
          {
            "events": [
              {
                "introduced": "11.0.0"
              },
              {
                "fixed": "12.0.0"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-8gr3-2gjw-jj7g",
        "severity": "high",
        "summary": "Hidden functionality in node-ipc",
        "ranges": []
      },
      {
        "id": "GHSA-97m3-w2cp-4xx6",
        "severity": "critical",
        "summary": "Embedded Malicious Code in node-ipc",
        "ranges": [
          {
            "events": [
              {
                "introduced": "10.1.1"
              },
              {
                "fixed": "10.1.3"
              }
            ]
          }
        ]
      },
      {
        "id": "MAL-2026-3744",
        "severity": "medium",
        "summary": "Malicious code in node-ipc (npm)",
        "ranges": []
      }
    ],
    "ua-parser-js": [
      {
        "id": "GHSA-394c-5j6w-4xmx",
        "severity": "high",
        "summary": "ua-parser-js Regular Expression Denial of Service vulnerability",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.7.23"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-662x-fhqg-9p8v",
        "severity": "high",
        "summary": "Regular Expression Denial of Service in ua-parser-js",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "0.7.22"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-78cj-fxph-m83p",
        "severity": "high",
        "summary": "Regular Expression Denial of Service (ReDoS) in ua-parser-js",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.7.14"
              },
              {
                "fixed": "0.7.24"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-9h5v-pfqq-x599",
        "severity": "high",
        "summary": "UAParser.js: Unbounded `Sec-CH-UA-Model` parsing can trigger ReDoS in `withClientHints()`",
        "ranges": [
          {
            "events": [
              {
                "introduced": "2.0.1"
              },
              {
                "fixed": "2.0.10"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-fhg7-m89q-25r3",
        "severity": "high",
        "summary": "ReDoS Vulnerability in ua-parser-js version",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.7.30"
              },
              {
                "fixed": "0.7.33"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0.8.0"
              },
              {
                "fixed": "1.0.33"
              }
            ]
          }
        ]
      },
      {
        "id": "GHSA-pjwm-rvh2-c87w",
        "severity": "high",
        "summary": "Embedded malware in ua-parser-js",
        "ranges": [
          {
            "events": [
              {
                "introduced": "0.7.29"
              },
              {
                "fixed": "0.7.30"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "0.8.0"
              },
              {
                "fixed": "0.8.1"
              }
            ]
          },
          {
            "events": [
              {
                "introduced": "1.0.0"
              },
              {
                "fixed": "1.0.1"
              }
            ]
          }
        ]
      }
    ],
    "coa": [
      {
        "id": "GHSA-73qr-pfmq-6rp8",
        "severity": "critical",
        "summary": "Embedded malware in coa",
        "ranges": []
      }
    ],
    "rc": [
      {
        "id": "GHSA-g2q5-5433-rhrf",
        "severity": "critical",
        "summary": "Embedded malware in rc",
        "ranges": []
      }
    ]
  }
};;

export const ACTION_PINS: { fetched: string; pins: Record<string, string>; note?: string } = {
  "fetched": "2026-10",
  "pins": {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "github/codeql-action": "3306ba4df796b6b5059316f3af8bdea1e2138c9b"
  },
  "note": "real commit SHAs via git ls-remote — update via --update-pins command (re-run build script)"
};
