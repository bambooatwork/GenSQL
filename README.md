# ⚡ GenSQL v2.0.0

```
  ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██╗
 ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔═══██╗██║
 ██║  ███╗█████╗  ██╔██╗ ██║███████╗██║   ██║██║
 ██║   ██║██╔══╝  ██║╚██╗██║╚════██║██║▄▄ ██║██║
 ╚██████╔╝███████╗██║ ╚████║███████║╚██████╔╝███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚══▀▀═╝ ╚══════╝

                    by Jeevraj
```

> **The most powerful web security assessment framework of 2026.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Version](https://img.shields.io/badge/Version-2.0.0-green)
![License](https://img.shields.io/badge/License-GPL--2.0-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Tests](https://img.shields.io/badge/Tests-53%2F53%20passing-brightgreen)

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Scan Profiles](#-scan-profiles)
- [All Flags](#-all-flags)
- [Architecture](#-architecture)
- [Legal](#-legal-disclaimer)

---

## 🚀 Features

### 🔥 Core Injection Engine
- **6 injection techniques**: Union-based, Error-based, Blind (binary-search — *50% fewer requests than sequential*), Bitwise (*only 8 requests per character*), Time-based, Stacked queries
- **6 DBMS fully supported**: MySQL/MariaDB, Microsoft SQL Server, PostgreSQL, Oracle, SQLite, MongoDB (NoSQL)
- **Auto DBMS fingerprinting** — detects database version, charset, and privileges
- **Hex-encoded payloads** — bypasses string-based WAF filters automatically
- **Parallel column dump** — multiple threads per table for maximum speed
- **Resume from checkpoint** — interrupted dumps continue from exact row offset

### 🛡️ Advanced WAF & HTTP Error Bypass (50+ techniques)
| Error Code | Techniques |
|-----------|-----------|
| **403 Forbidden** | IP header spoofing, URL override, path fuzzing, method switching, host header manipulation, chunked transfer encoding, double-slash traversal |
| **404 Not Found** | 40+ path variants (case, unicode, slash, extension, traversal), URL override headers |
| **429 Rate Limit** | Adaptive back-off with jitter, Retry-After compliance, identity rotation, agent rotation |
| **503 Unavailable** | Protocol switching (HTTP↔HTTPS), port variation, cache-busting |

**IP Spoofing Headers (20+):** `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-Addr`, `CF-Connecting-IP`, `True-Client-IP`, `X-Azure-ClientIP`, `Fastly-Client-IP` and more.

**URL Override Headers:** `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`, `Request-Uri`

**AI WAF Fingerprinting** — auto-detects: Cloudflare, Akamai, Imperva, AWS WAF, F5 BIG-IP, ModSecurity, Barracuda, Sucuri

### 💡 Smart Tamper Engine (30+ Techniques)
Auto-selects the best tamper chain per WAF and DBMS:

| Category | Tampers |
|---------|---------|
| **Whitespace** | `space2comment`, `space2dash`, `space2hash`, `space2mssqlblank`, `space2morehash` |
| **Encoding** | `base64_encode`, `double_urlencode`, `urlencode_all`, `unicode_encode`, `html_encode`, `hex_strings` |
| **Case/Comment** | `randomcase`, `randomcomments`, `inline_comment`, `modsec_versioned`, `modsec_zero_versioned` |
| **Logic** | `between_replace`, `equaltolike`, `greatest_replace`, `ifnull2ifisnull`, `scientific_notation` |
| **DBMS-specific** | `sp_password`, `plus2concat`, `versioned_keywords`, `concat_ws_bypass`, `mysql_comment` |
| **Obfuscation** | `null_byte_inject`, `apostrophe_mask`, `apostrophe_null`, `percentage_encode`, `evasion_multiline` |

### 🗄️ Database Extraction — Smarter and Faster
- **Binary-search blind** — halves the search space per character (log₂ faster than sequential)
- **Bitwise extraction** — exactly 8 requests per character, works through any delay
- **Error-based** — EXTRACTVALUE, UPDATEXML, CONVERT, FLOOR+RAND, UTL_INADDR (per DBMS)
- **Hex-encoded UNION** — extracts as hex then decodes client-side, bypasses string WAFs
- **Credential harvesting** — auto-targets `users`, `accounts`, `admin`, `wp_users`, `members` + 20 more
- **Hash identification** — detects MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, MySQL323, MySQL4.1+, MSSQL, Oracle, PostgreSQL hashes
- **Offline hash cracking** — dictionary, rule-based, mask, and rainbow table attacks (no internet)

**Export formats:** CSV · JSON · SQL INSERT statements · Dark-theme HTML with CVSS 4.0

### 🕸️ Modern Attack Surfaces
- **GraphQL** — introspection, batch queries, alias bypass, fragment injection, field suggestions
- **NoSQL** — MongoDB operator injection (`$where`, `$regex`, `$gt`), Redis, CouchDB
- **JWT** — `alg:none` bypass, RS256→HS256 confusion, `kid` path traversal + SQLi, weak secret bruteforce
- **gRPC-Web** — proto field injection via base64-encoded binary payloads
- **SSTI** — Jinja2, Twig, Freemarker, Velocity, Smarty detection + auto RCE chain
- **IDOR/BOLA** — sequential parameter enumeration with configurable range
- **REST API** — Swagger/OpenAPI guided scanning, parameter mining

### ☁️ Cloud & Serverless
- **AWS Lambda** — cold-start timing attacks, environment variable extraction
- **SSRF → Metadata** — auto-probe `169.254.169.254` for AWS/Azure/GCP secrets
- **Azure Functions / GCP Cloud Run** — serverless injection detection

### 🔍 Recon & Discovery
- **Deep OSINT** — crt.sh subdomain enumeration, Wayback Machine parameter mining
- **JS Analysis** — extracts hidden endpoints and parameters from JavaScript files
- **Passive subdomain enum** — certificate transparency logs
- **Parameter mining** — 1,000+ built-in parameter names tested automatically
- **Shodan integration** — extended recon with API key

### 🎯 Post-Exploitation Chain
```
SQL Injection
    → File Read (LOAD_FILE / COPY TO)
    → Webshell Upload (INTO OUTFILE)
    → OS Command Execution
    → Privilege Escalation Check
    → Credential Harvest
    → Lateral Movement Payloads
    → OOB Exfiltration (DNS / HTTP)
```

### 📊 Reporting
- **CVSS 4.0** scoring for every finding
- **HTML report** — dark-themed, professional, with masked sensitive data
- **JSON report** — machine-readable for integration with other tools
- **Markdown report** — for GitHub/Notion/Confluence
- **SQL INSERT export** — ready to import into your own database
- **Real-time dashboard** — web UI at `http://localhost:7474`

---

## 📦 Installation

```bash
# Clone
git clone https://github.com/bambooatwork/GenSQL.git
cd GenSQL

# Python 3.8+ required (no extra dependencies for core features)
python --version

# Optional dependencies for extra features
pip install httpx          # HTTP/2 async engine
pip install bcrypt         # bcrypt hash cracking

# Verify
python gensql.py --version
```

---

## ⚡ Quick Start

### Easiest: Interactive Wizard
```bash
python gensql.py --wizard
```
The wizard asks you 5 questions and launches the perfect scan.

### Basic SQL Injection Scan
```bash
python gensql.py -u "https://target.com/page?id=1"
```

### Full Database Dump (Fastest Method)
```bash
# Auto-detect best technique + hex encoding + parallel threads
python gensql.py -u "https://target.com/page?id=1" \
  --adv-dump --dump-hex --dump-parallel --dump-all-tables

# Dump only credential tables
python gensql.py -u "https://target.com/page?id=1" \
  --adv-dump --dump-creds --dump-output creds.html
```

### Bypass WAF + Firewall
```bash
# Auto-bypass any HTTP error (403/404/429/503)
python gensql.py -u "https://target.com/page?id=1" \
  --auto-bypass --ai-waf-bypass --ai-assist

# Bypass 403 on a specific URL
python gensql.py --bypass-403 --bypass-url "https://target.com/admin"
```

### Modern Attack Surfaces
```bash
# GraphQL
python gensql.py -u "https://target.com/graphql" \
  --graphql-inject --graphql-introspect

# NoSQL / MongoDB
python gensql.py -u "https://target.com/api/login" \
  --nosql-inject --nosql-type mongodb

# JWT attacks
python gensql.py -u "https://target.com/api" \
  --jwt-attack --jwt-bruteforce

# SSTI → RCE
python gensql.py -u "https://target.com/render?name=test" \
  --ssti-inject
```

### Cloud Targets
```bash
python gensql.py -u "https://api.target.com/" \
  --cloud-scan --ssrf-metadata --cloud-provider aws
```

### Full Pentest
```bash
python gensql.py -u "https://target.com/page?id=1" --profile pentest
# Runs: AI engine + WAF bypass + recon + all injection types +
#       exploit chain + credential harvest + HTML report
```

---

## 🎯 Scan Profiles

| Profile | Best For | What It Enables |
|---------|---------|----------------|
| `--profile stealth` | Evading IDS/WAF | Humanized timing, identity rotation, AI WAF bypass |
| `--profile api` | REST/GraphQL APIs | GraphQL, NoSQL, JWT, gRPC, IDOR, param mining |
| `--profile cloud` | AWS/Azure/GCP | Cloud scan, SSRF metadata, Lambda cold-start |
| `--profile pentest` | Full engagements | Everything + exploit chain + CVSS 4.0 HTML report |
| `--profile aggressive` | CTF / labs | Maximum speed, all techniques, OOB exfil |
| `--profile dump` | Database extraction | All dump techniques + credential harvest + export |

```bash
python gensql.py -u "https://target.com/?id=1" --profile dump
```

---

## 🚩 All Flags

### AI & Engine
| Flag | Description |
|------|-------------|
| `--ai-assist` | Offline AI payload mutation (no internet needed) |
| `--ai-learn` | Adaptive learning from each HTTP response |
| `--async-engine` | HTTP/2 async concurrent scan engine |
| `--http2` | Force HTTP/2 protocol |
| `--max-concurrent N` | Max concurrent requests (default: 50) |
| `--ai-top-payloads N` | Print top N AI-scored payloads after scan |

### WAF & HTTP Error Bypass
| Flag | Description |
|------|-------------|
| `--ai-waf-bypass` | AI WAF evasion (Cloudflare/Akamai/Imperva/AWS/F5) |
| `--bypass-403` | Auto-bypass 403 Forbidden (50+ techniques) |
| `--bypass-404` | Auto-bypass 404 Not Found (path fuzzing) |
| `--bypass-429` | Auto-bypass 429 Rate Limit (rotation + back-off) |
| `--bypass-503` | Auto-bypass 503 Service Unavailable |
| `--auto-bypass` | Auto-detect and bypass all HTTP errors |
| `--bypass-url URL` | URL to run bypass engine on (standalone) |
| `--humanize` | Humanized request timing |
| `--chunked-bypass` | Chunked transfer encoding bypass |
| `--rotate-identity N` | Rotate identity every N requests |
| `--encoder-chain CHAIN` | Encoder chain e.g. `url,base64,hex` |

### Advanced Database Dump
| Flag | Description |
|------|-------------|
| `--adv-dump` | Use GenSQL advanced dump engine |
| `--dump-technique MODE` | `auto`/`union`/`error`/`blind`/`bitwise`/`time` |
| `--dump-hex` | Hex-encode payloads (bypasses string WAF rules) |
| `--dump-blind` | Force binary-search blind extraction |
| `--dump-bitwise` | Force bitwise extraction (8 req/char) |
| `--dump-time` | Force time-based extraction |
| `--dump-error` | Force error-based extraction |
| `--dump-parallel` | Dump multiple tables in parallel |
| `--dump-creds` | Focus on credential tables |
| `--dump-all-tables` | Enumerate and dump all tables |
| `--dump-table TABLE` | Specific table to dump |
| `--dump-columns COLS` | Comma-separated column names |
| `--dump-threads N` | Parallel dump threads (default: 4) |
| `--dump-chunk N` | Rows per request chunk (default: 50) |
| `--dump-resume` | Resume interrupted dump |
| `--dump-output FILE` | Export to .csv/.json/.sql/.html |

### Injection Techniques
| Flag | Description |
|------|-------------|
| `--graphql-inject` | GraphQL injection |
| `--graphql-introspect` | Full schema introspection first |
| `--nosql-inject` | NoSQL injection |
| `--nosql-type TYPE` | `mongodb`/`couchdb`/`redis` |
| `--jwt-attack` | JWT attack suite |
| `--jwt-bruteforce` | JWT secret bruteforce |
| `--grpc-inject` | gRPC-Web injection |
| `--ssti-inject` | SSTI + auto RCE |
| `--idor-scan` | IDOR/BOLA enumeration |
| `--idor-range RANGE` | ID range e.g. `1-10000` |

### Cloud & API
| Flag | Description |
|------|-------------|
| `--cloud-scan` | Cloud/serverless injection |
| `--cloud-provider PROVIDER` | `aws`/`azure`/`gcp`/`auto` |
| `--lambda-cold-start` | Lambda cold-start timing attack |
| `--ssrf-metadata` | SSRF to cloud metadata |
| `--swagger-url URL` | OpenAPI/Swagger spec for guided scan |

### Recon
| Flag | Description |
|------|-------------|
| `--deep-recon` | Full OSINT recon |
| `--wayback` | Wayback Machine parameter mining |
| `--js-analysis` | JS endpoint/parameter extraction |
| `--subdomain-enum` | Passive subdomain enumeration |
| `--param-mine` | Parameter mining (1000+ names) |
| `--shodan-key KEY` | Shodan API key |

### Post-Exploitation
| Flag | Description |
|------|-------------|
| `--exploit-chain` | SQLi → webshell → OS command |
| `--harvest-creds` | Extract credentials from dump |
| `--privesc-check` | DB privilege escalation |
| `--lateral-move` | Lateral movement payloads |
| `--oob-exfil` | OOB DNS/HTTP exfiltration |
| `--oob-domain DOMAIN` | Callback domain |
| `--oob-listen PORT` | Built-in OOB listener |

### Reporting
| Flag | Description |
|------|-------------|
| `--report-html FILE` | HTML report with CVSS 4.0 |
| `--report-json FILE` | JSON report |
| `--report-md FILE` | Markdown report |
| `--cvss4` | Include CVSS 4.0 scores |
| `--dashboard` | Real-time web dashboard |
| `--dashboard-port PORT` | Dashboard port (default: 7474) |

### Profiles & Wizard
| Flag | Description |
|------|-------------|
| `--profile NAME` | `stealth`/`api`/`cloud`/`pentest`/`aggressive`/`dump` |
| `--wizard` | Interactive guided wizard |

---

## 🏗️ Architecture

```
GenSQL v2.0.0
├── gensql.py                      ← Main entry point
├── lib/
│   ├── core/
│   │   ├── ai_engine.py           ← Offline AI payload mutation
│   │   ├── async_engine.py        ← HTTP/2 concurrent engine
│   │   └── settings.py            ← Configuration + GenSQL banner
│   ├── evasion/
│   │   ├── ai_waf_bypass.py       ← AI WAF fingerprint + evasion
│   │   └── encoder_chain.py       ← Encoder chain (url/base64/hex/...)
│   ├── techniques/
│   │   ├── bypass/
│   │   │   ├── http_error_bypass.py  ← 403/404/429/503 bypass (50+ techniques)
│   │   │   └── smart_tamper.py    ← 30+ smart tamper functions
│   │   ├── dump/
│   │   │   ├── advanced_dump.py   ← Binary/bitwise/hex/parallel dump
│   │   │   └── hash_cracker.py    ← Offline hash identification + cracking
│   │   ├── graphql/               ← GraphQL injection
│   │   ├── nosql/                 ← MongoDB/CouchDB/Redis injection
│   │   ├── auth/                  ← JWT attacks
│   │   ├── api/                   ← REST + gRPC injection
│   │   ├── ssti/                  ← SSTI → RCE chain
│   │   └── cloud/                 ← AWS/Azure/GCP injection
│   ├── recon/
│   │   ├── deep_recon.py          ← OSINT + Wayback + JS analysis
│   │   └── param_miner.py         ← Parameter discovery
│   ├── exploit/
│   │   ├── chain.py               ← SQLi → webshell → OS chain
│   │   └── oob.py                 ← OOB DNS/HTTP exfiltration
│   └── report/
│       ├── report_engine.py       ← CVSS 4.0 HTML/JSON/MD reports
│       └── dashboard.py           ← Real-time web dashboard
```

---

## ⚖️ Legal Disclaimer

Usage of GenSQL for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. The author (Jeevraj) assumes no liability and is not responsible for any misuse or damage caused by this tool.

**Use only on systems you own or have explicit written permission to test.**

---

## 👤 Author

**Jeevraj**  
GitHub: [bambooatwork/GenSQL](https://github.com/bambooatwork/GenSQL)

---

*GenSQL v2.0.0 — Built for 2026 and beyond.*
