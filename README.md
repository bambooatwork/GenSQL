# GenSQL — Next-Generation SQL Injection & Web Security Assessment Framework

```
  ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██╗
 ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔═══██╗██║
 ██║  ███╗█████╗  ██╔██╗ ██║███████╗██║   ██║██║
 ██║   ██║██╔══╝  ██║╚██╗██║╚════██║██║▄▄ ██║██║
 ╚██████╔╝███████╗██║ ╚████║███████║╚██████╔╝███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚══▀▀═╝ ╚══════╝

                     by Jeevraj
```

> **Version:** 2.0.0 &nbsp;|&nbsp; **Author:** Jeevraj &nbsp;|&nbsp; Built on sqlmap · Far beyond in every way

---

## What is GenSQL?

GenSQL is a next-generation SQL injection and web security assessment framework built for the 2026 threat landscape. It goes far beyond sqlmap by adding an **offline AI mutation engine**, **async HTTP/2 scanning**, support for **GraphQL / NoSQL / JWT / gRPC / SSTI / Cloud** injection, deep OSINT recon, full exploit chaining, and rich HTML/JSON reports — all with zero cloud dependencies.

---

## Quick Start

```bash
# Basic scan
python gensql.py -u "https://target.com/page?id=1"

# Interactive wizard
python gensql.py --wizard

# Full pentest profile (everything enabled)
python gensql.py -u "https://target.com/page?id=1" --profile pentest

# Stealth mode with AI WAF bypass
python gensql.py -u "https://target.com/page?id=1" --profile stealth

# API-focused scan
python gensql.py -u "https://target.com/api" --profile api
```

---

## New Features vs sqlmap

| Feature | sqlmap | GenSQL |
|---------|:------:|:------:|
| Offline AI payload mutation | ❌ | ✅ |
| Async HTTP/2 engine (50 concurrent) | ❌ | ✅ |
| AI-powered WAF bypass | ❌ | ✅ |
| GraphQL injection | ❌ | ✅ |
| NoSQL injection (MongoDB etc.) | ❌ | ✅ |
| JWT attacks (alg:none, RS256→HS256, kid SQLi) | ❌ | ✅ |
| gRPC-Web injection | ❌ | ✅ |
| SSTI detection + auto-RCE chain | ❌ | ✅ |
| Cloud/Lambda/Serverless injection | ❌ | ✅ |
| SSRF to metadata service | ❌ | ✅ |
| Deep OSINT recon (crt.sh, Wayback, JS) | ❌ | ✅ |
| Parameter mining (1000+ built-in) | ❌ | ✅ |
| Exploit chain (SQLi → RCE → lateral) | ❌ | ✅ |
| OOB exfiltration (DNS + HTTP listener) | Partial | ✅ |
| CVSS 4.0 scoring | ❌ | ✅ |
| HTML/JSON/Markdown reports | ❌ | ✅ |
| Real-time web dashboard | ❌ | ✅ |
| CockroachDB / TiDB / ClickHouse | ❌ | ✅ |
| 100+ tamper scripts | 50+ | ✅ |

---

## New Modules

### 🧠 AI Engine (`lib/core/ai_engine.py`)
Fully **offline** payload mutation and WAF detection — no API keys, no internet required.
- 200+ SQL injection payload templates across 5 DBMS
- Grammar-based mutation (whitespace, comments, case, encoding, scientific notation)
- WAF fingerprinting for 11 WAF products
- Payload scoring and adaptive learning

### ⚡ Async Engine (`lib/core/async_engine.py`)
HTTP/2-capable concurrent scan engine with up to 50 parallel connections, adaptive rate limiting, and automatic retry with exponential backoff.

### 🛡️ WAF Bypass (`lib/evasion/ai_waf_bypass.py`)
600+ User-Agent strings, JA3 fingerprint rotation, request humanisation, 8 WAF-specific strategy tables (Cloudflare, Akamai, Imperva, AWS WAF, F5, ModSecurity, Sucuri, Barracuda).

### 🔗 Injection Techniques
| Module | Attacks |
|--------|---------|
| `lib/techniques/graphql/` | Introspection, batch, alias flooding, fragment, persisted query injection |
| `lib/techniques/nosql/` | Operator injection, `$where` JS, ReDoS, blind boolean, auth bypass |
| `lib/techniques/auth/` | JWT alg:none, RS256→HS256, kid SQLi, path traversal, weak secret bruteforce |
| `lib/techniques/api/` | REST HPP, JSON body, IDOR/BOLA, mass assignment, gRPC proto field injection |
| `lib/techniques/cloud/` | Lambda cold-start timing, API Gateway, Azure Functions, GCP, SSRF-to-metadata |
| `lib/techniques/ssti/` | Jinja2, Twig, Freemarker, Mako, Smarty, Velocity, ERB — auto-chain to RCE |

### 🔍 Recon
- **Deep OSINT** — crt.sh certificate transparency, Wayback Machine parameters, JS endpoint extraction, cloud provider detection, attack surface mapping
- **Param Miner** — 1000+ built-in parameter names, header mining, JSON field discovery, Swagger/OpenAPI guided

### 💥 Post-Exploitation
- **Exploit Chain** — SQLi → file read → webshell upload → OS command execution → credential harvesting → lateral movement payloads
- **OOB Exfiltration** — DNS and HTTP out-of-band with built-in HTTP listener server; DBMS-specific payloads for MySQL, MSSQL, PostgreSQL, Oracle

### 📊 Reporting
- Dark-theme HTML report with CVSS 4.0 scoring
- JSON and Markdown output
- Real-time web dashboard at `http://127.0.0.1:7474`

---

## New DBMS Support

| Database | Port | Protocol |
|----------|------|----------|
| **CockroachDB** | 26257 | PostgreSQL wire |
| **TiDB** | 4000 | MySQL wire |
| **ClickHouse** | 8123/9000 | Native HTTP |

---

## Scan Profiles

```bash
--profile stealth     # Humanised requests, identity rotation, AI WAF bypass
--profile api         # GraphQL, NoSQL, JWT, gRPC, IDOR, param mining
--profile cloud       # Cloud/Lambda/serverless injection, SSRF, deep recon
--profile pentest     # Everything + exploit chain + CVSS 4.0 HTML+JSON reports
--profile aggressive  # All attack modules + cred harvest + lateral movement
```

---

## New Flags (selection)

```
--ai-assist           Offline AI payload mutation engine
--ai-waf-bypass       AI-powered WAF evasion
--async-engine        HTTP/2 async concurrent engine
--graphql-inject      GraphQL injection + introspection
--nosql-inject        NoSQL injection (MongoDB, CouchDB, Redis)
--jwt-attack          JWT attack suite
--grpc-inject         gRPC-Web proto field injection
--ssti-inject         SSTI detection + auto RCE chain
--cloud-scan          Cloud/serverless injection
--ssrf-metadata       SSRF to cloud metadata service
--deep-recon          OSINT recon (crt.sh, Wayback, JS analysis)
--param-mine          Parameter mining (1000+ names)
--exploit-chain       SQLi to RCE exploit chain
--harvest-creds       Credential harvesting from SQLi
--oob-exfil           Out-of-band exfiltration
--oob-domain DOMAIN   DNS callback domain for OOB
--oob-listen PORT     Start built-in HTTP OOB listener
--report-html FILE    Generate HTML report with CVSS 4.0
--report-json FILE    Generate JSON report
--report-md FILE      Generate Markdown report
--dashboard           Start real-time web dashboard
--dashboard-port PORT Dashboard port (default: 7474)
--wizard              Interactive guided setup wizard
--profile NAME        Apply scan profile (stealth/api/cloud/pentest/aggressive)
```

---

## Requirements

```
Python 3.8+
No additional dependencies required for core functionality.

Optional (for enhanced features):
  httpx       - HTTP/2 support in async engine
  psycopg2    - CockroachDB direct connection
  pymysql     - TiDB direct connection
```

---

## Legal Disclaimer

GenSQL is provided for **authorized penetration testing and security research only**.
Unauthorized use against systems you do not own or have explicit permission to test is illegal.
The author (Jeevraj) assumes no liability for misuse of this tool.

---

*GenSQL v2.0.0 — by Jeevraj — Next-Generation SQL Injection & Web Security Assessment Framework*
