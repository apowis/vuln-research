# LinkedIn series: findings catalogue (Aug-Nov 2026)

Collated 2026-11-23 from memory notes, ~40 claude.ai artifacts, Claude Code transcripts and this
branch's `findings.md` (finding numbers like F1-F21 refer to that file). Internal: the catalogue
names embargoed bugs and customer-derived work. Check [`publication-rules.md`](publication-rules.md)
before drafting any post.

**Status tags**

- `READY`: public-safe as aggregates. No IPs, no org names.
- `REWORD`: publishable once wording or anonymisation is fixed (JA4TS -> "TCP stack fingerprint",
  no "IP intelligence", no org names, mark illustrative numbers).
- `GATED`: waiting on a CVE id, vendor advisory, rule deployment or confirmation.
- `EMBARGO`: undisclosed vulnerability. Do not post until coordinated disclosure finishes.
- `INTERNAL`: customer-specific or engineering-only. At most a generic lesson.

---

## 1. Memory leaks and vulnerability discovery (passive hunting + strict-spec "formal verification")

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 1.1 | **coturn 4.10.0 ERROR-CODE reason-phrase stack leak: our own CVE-2026-104074 (VulnCheck CNA)**. A fix for an optional field skipped zeroing a stack buffer. (F1) | 58 hosts at discovery, ~3% of error responders; blind re-find 906 hosts, 72% pointer-like; fixed 4.11.0 | READY (confirm CVE published) |
| 1.2 | **"A memory leak in a fix for a memory leak"**: coturn 4.10.0 regressed the CVE-2020-4067 class. Plus why we chose *not* to build an exploit (valgrind-only, no repro) | same | READY |
| 1.3 | **DrayTek Vigor OpenVPN udp/1194 stale-ack leak**: our broken probe "fuzzed the internet for nine months" and found it (F2) | 106,227 hosts in 30d (a floor); 65k of 200k echoers leak; whole DrayOS 3.9.3-4.5.3; reported 2026-10-22, fix verified on V2865 beta 10-28 | GATED (CVE + advisory) |
| 1.4 | **Cisco ASA/FTD IKEv1 INVALID-COOKIE stack over-read**: one 28-byte packet returns 28 bytes of process stack, with pointers that defeat ASLR. Reproduced in the lab on ASA 9.16/9.22/9.24, root cause found, no key material | ~4.9k hosts; 84-97% of ASAs that answer IKEv1 | EMBARGO (not reported to PSIRT) |
| 1.5 | **BENIGNCERTAIN rediscovered**: Cisco IOS IKEv1 notify heap leak = CVE-2016-6415 (KEV). Fixing our probes made it start firing (F3) | 10,876 IPs, 1-11 Nov | GATED (CNA decision, airf-rules#1520) |
| 1.6 | **Cisco IOS PPTP hostname leak, CVE-2016-6398**: never fixed by Cisco, still leaks login prompts, typed usernames and RADIUS AVPs (F4) | 4,787 of 11,596 Cisco PPTP IPs (41%); 11-23 re-run 7,482/17,775 | READY (never quote leaked bytes) |
| 1.7 | **ABB AC500 Modbus slack, CVE-2025-7745 re-found blind** from raw bytes (credit Dragos/Reid Wightman), plus 302 fake "PM573-ETH V2.7.1" honeypot PLCs (F5, F13) | 32 hosts/60d; fixed 2.5.3 | READY |
| 1.8 | **Teco Tecomat PLCs hand one client's Modbus registers to another**: oversized exception replies cross connections (F6) | 29 hosts/240d; marker returned 24 of 25; web v5.7-9.0 leak, v10.3+ fixed | EMBARGO (draft advisory, vendor not contacted) |
| 1.9 | **Strict-spec runs on 8 protocols** (Kaitai specs as BigQuery UDFs, ~$0): 5 new leaks, 4 known CVEs re-found with no hints. The method post | Modbus 33k services (28,928 clean / 937 slack / 913 malformed); STUN 283,948; SNMP 12.7M rows; PPTP 2.07M replies | READY as method (keep new leaks generic) |
| 1.10 | **CVE-2020-4067 re-found blind**: coturn SOFTWARE padding. Version strings lie (distro backports) | 4,106 of 283,948 leak; 4.5.1.2 75% vs 4.5.1.1 11% vs 4.5.1.3 1.5% | READY |
| 1.11 | **"Citrix 3.2.x" TURN servers are really rfc5766-turn-server**, invisible to CVE-2020-4067 matching | 1,271 of 1,312 leak (97%) | READY-ish (abandoned OSS; check the CNA brief) |
| 1.12 | **Amazon Connect TURN fleet leaks the same padding** | 168 of 168 hosts | EMBARGO (AWS report pending) |
| 1.13 | **CODESYS V3 stale ARM pointer in the channel-open reply**: root cause traced in WAGO firmware source, fixed silently in 3.5.18.20 | ~640 of 2,757 V3 hosts | EMBARGO (advisory check pending) |
| 1.14 | **BDCOM routers quoted our own login attempt back to us**: PPTP vendor-field tail holds syslog, SNMP and 401 pages | 5 of 95-99 BDCOM hosts, every scan | EMBARGO |
| 1.15 | **Enterasys X-Pedition PPTP tail leak** (EOL) | 6/6 IPs | EMBARGO (EOL; low priority) |
| 1.16 | **Harris ZX FM transmitter: the SNMP agent leaks its own web page** | 1 host | EMBARGO (single host; broadcast infra) |
| 1.17 | **3proxy SOCKS4 pointer leak (CVE-2026-109438, a teammate's find)**: one process behind thousands of IPs | 7,928 IPs leaked at least once in 30d; 6,405 share constants | GATED (teammate write-up) |
| 1.18 | **Ericom AccessPad: one click on an estp:// link drives the client to an attacker's RDP server** (CVSS 9.6), plus a hard-coded AES key (9.0) and a TLS client that accepts any cert. AI-assisted research "with receipts", including one hypothesis we debunked | lab-confirmed on 9.5.0.60672; ESG rule found 748 IPs | EMBARGO (Ericom not contacted) |
| 1.19 | **eMudhra emBridge installers ship a live, publicly-trusted Sectigo cert plus private key** | Mac build currently valid, unrevoked | EMBARGO |
| 1.20 | **eMudhra G3 intermediates: validly-signed certs for Yandex/Baidu/Sogou with zero SCTs** | detector = G3 SKI + no SCT + first_seen >= 10-20 | EMBARGO |
| 1.21 | **Leads that turned out benign**: VDH Modbus "leak" was a counter (sum mod 256); NetBIOS MYSTORAGE churn was our own txid echoed; IKE "leak" was CSPRNG cookies. "Probe a random byte several times before calling it memory" | VDH 29 hosts, 181/184 counter steps exact; NetBIOS 111 hosts | READY (good honesty post) |
| 1.22 | **Clean negatives at scale**: SNMPv3 (11M hosts), LDAP (60k), NTP, FTP/SMTP/IMAP/POP3, BGP, mDNS. "Clean for the checks we ran" | see findings.md | READY |

## 2. Honeypots, decoys and deception fleets

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 2.1 | **One honeypot network, six fingerprints**: an AWS sensor network unmasked by a Redis server whose clock never moves, 34 persona pages, forged certs and Twisted SSH posing as OpenSSH | 20,100 IPs, ~1-day IP lifetime, 98.5% AWS; Redis uptime 75615 on 2,138/2,138; 0 outside AWS | READY (operator unattributed; think before publishing the exact tells) |
| 2.2 | **We counted the internet's supermarket fridges, and one in six was a trap** | 3,023 refrigeration-controller IPs; ~500 honeypots (PlantVisor 211/222, Danfoss AK-SM 252/903); 99% of real ones expose only a web UI; 4 new rules | READY |
| 2.3 | **A 526-IP LiteSpeed fleet pretending to be 15 edge appliances** (found by a failing Dataform assertion) | 526 IPs, 991 ports, 56 body templates; one host had 1,124 CVEs at tier 20+ | REWORD (drop "ipintel") |
| 2.4 | **Honeypots inflate CVE and product statistics**: Sun ONE (525), NetScaler "6.1", Sysax SSH on 5,844 Alibaba IPs; IPs with 10+ identity products drive half of some product counts | 16k deception IPs | READY |
| 2.5 | **JDWP decoys**: ~9.5k Alibaba hosts send "JDWP-Handshake" first; the real debuggers are ~48 | ~9.5k; port 8000 1,157 | READY |
| 2.6 | **113 servers, one recording**: an NTP monlist honeypot fleet replays one 440-byte reply that preserves an old ntpd leak | 113 hosts, ~30 countries | READY |
| 2.7 | **Modbus "Generic Vendor / MODBUS-001" fleet**: the unexplained cluster explained by its own placeholder strings (F11) | 109 hosts, 76% AS174 | READY |
| 2.8 | **DNS-shaped replies on 45 non-DNS UDP ports**: a honeypot fleet that creates ICS false positives (F12) | 1,784 hosts; 357 tagged Modbus | READY |
| 2.9 | **Repeated "random" nonces as honeypot tells**: MySQL salt `aaaaaaaa`, `0102030405060708`, frozen IPsec SPIs | 109 / 28 / 12 hosts | READY |
| 2.10 | **RMI/JRMP scanner day 1: ~70% honeypots**; real hosts leak internal hostnames via bound names | 403 IPs after 2 days | READY |
| 2.11 | **SNMP "ZIPOne" templated honeypot** (fresh engine ID per reply) and CODESYS V2 decoy farms | 18-26 hosts/month | READY |
| 2.12 | **PHP2Shell: how many of ~2M CVE-2026-109619 hits are honeypots?** (10-22 assessment) | ~2M fingerprint hits | GATED (numbers not yet pulled) |

## 3. Certificates, forgery and the cert graph

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 3.1 | **Forged "CDN edge" cert campaign**: one key per leaf, Go listeners dressed as nginx | 874 hosts, 75 ASNs, 24 countries, live since 2026-03-10; 0 previously known | READY (actor unknown; don't claim C2) |
| 3.2 | **Luxury-brand forged DigiCert batch: 28,031 hosts, one signing key, 111x undercount in a 30-day view** | 28,031 hosts vs 252 active in 30d | READY (brand-name care) |
| 3.3 | **Forged certs are CA/B-compliant**: lint scores zero, and only "did anyone vouch for it" (SCTs, logged keys) works. A detector playbook | 66 of 67 forged certs 396d; 39 DER-verified, all zero SCT | READY |
| 3.4 | **Three more forged-cert generators from the graph**: fake Let's Encrypt X3 on DigitalOcean, 1,329 GlobalSign IP-CN leaves, Cloudflare origin exposure | 2.1M certs on >1 host; 323k cert moves Aug-Sep | READY |
| 3.5 | **Shared private keys baked into firmware** | 15,519 hosts on 1,083 keys; QNAP 7.7k hosts on one key; Hikvision 789; Canon 1,377; Mitel 1,198 certs | READY (vendor-name care) |
| 3.6 | **Three-quarters of the internet's TLS is TV boxes**: Widevine Cast devices on port 9000 | 2.70M of ~3.58M real-TLS ip:ports | READY |
| 3.7 | **Cloud IP reuse breaks cert-based attribution**: 9 of 10 "banks running PHP2Shell" were churned AWS tenants | 82,219 bank-cert IPs -> 10 matches -> 2 credible | REWORD (no bank names) |
| 3.8 | **Certificate identity beats domain suffix for mapping a government**: abbreviation collisions (1,906 of 2,539 "Belgian government" hosts were not) | NL 3,849 hosts / 244 orgs | REWORD ("a national government") |
| 3.9 | **Our cert table silently lost 1.19% of certs** (32-bit rowkey), which created false forgery leads | 1,223,093 certs | READY (honest engineering) |
| 3.10 | **Certificate Transparency firehose**: 362M entries/day, 7 logs cover 98% | | READY |

## 4. Weird protocol data, and our own scanner as the weirdest thing in it

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 4.1 | **"We nearly published a botnet that was a typo"**: hex-escape bug corrupted 58 of 84 UDP probes for 9 months, and the echoes looked like a campaign (F16) | 166k hosts echo mangled RPCCheck; 127k DNS FORMERR; fixed #4704 | READY |
| 4.2 | **Echo contamination**: up to 63% of a protocol table was our own probes (dnp3 63%, rocketmq 30%, codesys 25%) (F17) | 922k unknown rows | READY |
| 4.3 | **A host that replays the previous client's bytes**, and other replay classes (F18-19) | | READY |
| 4.4 | **Darklantern UDP echo**: why you shouldn't fingerprint malware by a property of its network (F15) | 21,149 echoers; "2+ ports" only 34% precise | REWORD (no "honeypot sensors" as fact) |
| 4.5 | **OpenClaw AI gateways answering mDNS from the internet**: the HTTP rule missed 98.9% (F7) | 1,434-2,789 hosts, 183 ASNs, 41 countries | REWORD (drop "ipintel") |
| 4.6 | **Webmin MiniServ udp/10000 reply**, plus a bug in our own Webmin rules (F8) | 17.9k UDP; ~80k newly identified | READY |
| 4.7 | **QNAP HBS 3 RTRR frame on tcp/8899**, identified by firmware teardown (F9) | 2,072 hosts | READY |
| 4.8 | **The unknown pot as a discovery engine**: 300k FortiGates send ClientHellos on 541; Avigilon PACS; Xray nodes with SNI `honey-agent` | 314,996 ClientHello senders | READY |
| 4.9 | **mDNS on the open internet**: Android phones broadcasting WiFi band, Mysterium dVPN, fnOS, Avigilon, SK Broadband set-tops | 720 / 61 / 62 / 35 / 6.6k hosts; 1.91M responders | READY |
| 4.10 | **BGP quirks**: Check Point Gaia, AS_TRANS RFC violations, a bogus router id shared by 289 peers | 1,938 AS_TRANS hosts | READY |
| 4.11 | **Repeated values reveal shared keys and products**: Dropbear key on 5,098 ISP CPEs, Synology SRM clock 2009-04-22 | 5,098 / 139 hosts | READY |
| 4.12 | **A rogue JNDI exploit LDAP server** found during the LDAP leak sweep | 1 host, live 10-22 to 11-19 | REWORD (no IP) |
| 4.13 | **"The weird-data hunt that found no implant, and why that is a result"** | 23 ranked clusters, $1.25 | READY |

## 5. Fingerprinting and detection wins

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 5.1 | **300,000 FortiGates leak their firmware era in one ClientHello** (FGFM tcp/541, five generations). Also: the FortiJump hunch was wrong, and FortiManager was over-counted 200x | 302,225 bucketed; Gen5 30.7% / Gen4 32.6% / Gen3 29.8%; 149,959 false FortiManager | READY (draft blog exists) |
| 5.2 | **376k Windows hosts versioned from RDP NTLM alone** | 412.9k carry OS build; 91% had no versioned CPE; 12.8% EOL 6.x | READY |
| 5.3 | **One malformed reply identifies a million routers**: Cisco IP SLA responders on udp/1967 | ~946k host-windows; 47-73% have no SNMP | READY |
| 5.4 | **91.5% of SNMP responders give only a v3 engine ID**, so the PEN is the lever; v3 discovery never ran | 8.67M of 9.48M; ~1.2M hosts newly labelled | READY |
| 5.5 | **Cisco NX-OS gives itself away**: SNMP msgMaxSize 65507 + 161/tcp | 26,606 vs 431,608 | REWORD (no JA4TS) |
| 5.6 | **Offensive AI tooling exposed, and caught attacking us**: 12 new fingerprints; a PentAGI console fired a KEV exploit at our canaries | 2,861 hosts; 68% HK/SG/CN; 291 otherwise unidentified | READY |
| 5.7 | **Juniper SSR waypoint-port signature**: the baseline that makes real BACnet/ENIP replies look rare | ~33.5k IPs/90d; ~8.9k share a constant HMAC | READY (don't repeat probes) |
| 5.8 | **Firmware build date hidden in a JavaScript timestamp** (QNAP qnap-lib.js `_dc`); a versionless QNAP rule matched 59k hosts and joined zero CVEs | 59,278 IPs; ~36-55k hosts gain CVEs | READY |
| 5.9 | **Check Point build stamp on 18264 is the install-image date, not the patch level** | 2,490 stamps / ~24k hosts | READY |
| 5.10 | **Header-stripped edge appliances hide a third of a government's web surface**: 16 rules lift identification from 70% to 85% | BIG-IP 205 -> ~700 | REWORD (anonymise; no JA4TS) |
| 5.11 | **Default pages give away the OS**: Apache/nginx default-page titles | Raspbian 4.3k | READY |
| 5.12 | **ASUS routers: 81% expose no version signal, ever** | 2.3% of 112k resolve a version | READY |
| 5.13 | **AnyDesk direct listeners** (mutual TLS, TLS-stack version band) | ~55k ip:ports | READY |
| 5.14 | **Smaller version sources**: Yellowfin /JsAPI, BeyondTrust get_rdf (85% withhold), Ericom GetStringTable, Terrakube version bracketing via release-tag diffs, ASP.NET error pages leaking the .NET build | | READY (strip customer hosts) |
| 5.15 | **Legacy JS libraries**: the IE shim stack and jQuery plugins dwarf the library everyone searched for | airf-rules#1560/#1562 | READY |
| 5.16 | **BMC / out-of-band gaps**: iLO rule gave 4,644 hosts decade-old CVEs; 32k IPMI replies unparsed | | GATED (check fix) |
| 5.17 | **Attacker-infra label audit**: 9,491 "Starkiller C2" hits were all false; one HTTP header (Flussonic) was 40% of the feed; "cdn:google" matched GCP customer VMs | ~15 real C2 after fix; ~8.4k IPs relabelled | REWORD (aggregate only) |

## 6. Exposure and CVE intelligence (anonymised patterns from reports)

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 6.1 | **79% of observed KEV exposure is VulnCheck-KEV-only**; in two real estates 6 of 12 and 21 of 28 exploited CVEs were missing from CISA KEV | 46.68M of 59.3M | READY (no org names) |
| 6.2 | **"1,574 hosts with CVEs" is really 130**: confidence tiers | NL 1,096 CVEs on 1,574 hosts, 130 version-exact | READY as method |
| 6.3 | **The most-attacked CVE isn't in CISA KEV** (Next.js CVE-2025-29927) | 161,191 canary attempts / 30d | READY (canary counts are real; host counts illustrative) |
| 6.4 | **EPSS misleads**: 1% EPSS, in both KEV lists, working exploit; "not watched" is not "quiet" | Traefik 15,453 attempts | READY |
| 6.5 | **Canary vs scan coverage**: only 37% of canary-seen exploitation maps to a confirmed fingerprint | 575 CVEs | READY |
| 6.6 | **The no-CPE gap**: 28-29% of new CVEs have no CPE, so "0 CVEs" can mean "unknown" | 2025 29%, 2026 YTD 28% | READY |
| 6.7 | **NVD alias noise**: 1.84M IIS hosts "confirmed" for 1999-2007 CVEs; SharePoint flagged "ToolShell confirmed" on a patched build; letter-prefixed versions match every range | 1,841,731 hosts | READY (no customer) |
| 6.8 | **Oracle EBS CVE-2026-101767: the patch doesn't change the release number** | 193/376 affected, 181 hidden | READY (a teammate's piece) |
| 6.9 | **Linux kernel TCP handshake CVE: 641,824 Linux devices, not one kernel build visible** | 99.2% Dropbear | READY (a teammate's piece) |
| 6.10 | **php2shell: from KEV to botnet in a day** (canary timeline) | 7,367 hits from 292 IPs in 8 days | READY (strip government context) |
| 6.11 | **Bank exposure is mostly CDN edges wearing the bank's certs** | 7,083 hosts; 5,416 CDN; 7% expose a version | REWORD ("a large US bank") |
| 6.12 | **Zero CVEs is a measurement problem**: SNI-routed App Gateway backends never reach CVE scoring | 42 names -> 4 gateways | INTERNAL (generic lesson only; Org2) |
| 6.13 | **Mapping a network's layers from TCP stack mismatches, TTL and TCP timestamp clocks** | 6 device tiers | INTERNAL (Org3/Org4; method only, no JA4TS) |
| 6.14 | **Running down CitrixBleed 2 / React2Shell leads with benign probes**: the ethics of checking | | INTERNAL (method only) |

## 7. Behind the scanner (engineering and data-quality lessons)

| # | Finding | Key numbers | Status |
|---|---|---|---|
| 7.1 | **Fewer dials, more detections**: -70M connections/day; SSH 92.5% -> 100% identified, ~17k newly visible devices/day | silent job loss ~276k/day -> 4 in 96.9M | REWORD (it discloses past data loss) |
| 7.2 | **The ICS scanner that went blind because of 10 ms**: a zgrab2 read-timeout regression | fox 633 -> ~30/day; rdp 24,937 -> ~7,000 | READY |
| 7.3 | **All-ports-open hosts eat half of zgrab capacity and identify at 0.2%** | 50.1% of traces | READY |
| 7.4 | **Counting devices: why IPs lie**: 30-day counts ~19x daily; never sum hosts across days | MikroTik 886,871 vs ~48k/day | READY |
| 7.5 | **A zero hit count is not a negative**: sip.headers null on every row; ~90 dead cert rules; 372 suspect banner rules | 0 of 62,520 | READY |
| 7.6 | **zcrypto's cipher order depends on the CPU** (a droplet change silently flips server fingerprints) | ~230k configs | REWORD (no JA4S) |
| 7.7 | **617,350 SSH hosts say hello but never finish key exchange** | 2.8% host-level | READY |
| 7.8 | **Auto-generated detection rules: confidence score didn't predict human edits, ablation did** | 84 PRs, 79 merged | READY (don't claim cost savings) |
| 7.9 | **IKE: ML-KEM proposals make most stacks drop the datagram** | ~160k "IKEv1-only" hosts | READY |
| 7.10 | **MS-RPC: EPM never lies but dynamic ports are firewalled**; NTLM in a BIND leaks the OS build | spoolss 21% over-count | READY |

## 8. Firmware and reversing

| # | Finding | Status |
|---|---|---|
| 8.1 | DrayTek firmware: modified ChaCha with the key in the clear in 3.9.x u-boot | INTERNAL (never publish key or recipe) |
| 8.2 | FortiOS rootfs crypto differs per generation (lab) | INTERNAL (low LinkedIn value) |
| 8.3 | QNAP HBS3 qpkg static confirmation of the 8899 frame | READY (part of 4.7) |
| 8.4 | ASA lab repro on three versions | EMBARGO (part of 1.4) |

## 9. Open leads (not posts yet)

- tcp/6001 `taurus: /$` possible open shell on 2,202 KT Android boxes: unconfirmed, never enumerate.
- Foreign-txid Modbus replies (Robustel/KACO, Windows XAMPP): parked.
- tcp/5050 488-byte blob (4,721 hosts), tcp/8702 (29k KR), tcp/443 byte `0c` (2,222), 28-byte UDP blob (352).
- DrayTek TCP option kind 30 (2,819 hosts): possible second DrayTek leak.
- Stripe-lookalike long-validity self-signed certs.
- Copeland Site Supervisor BACnet: needs Who-Is (product#5387).

---

## What can run now

About 60 entries are `READY` or need only a light `REWORD`. Strongest public-safe hooks:

1. 2.1 One honeypot network, six fingerprints (the frozen Redis clock)
2. 2.2 Supermarket fridges: one in six is a trap
3. 4.1 The botnet that was a typo
4. 5.1 300k FortiGates leak their firmware era
5. 1.1/1.2 coturn: a leak in a fix for a leak (our CVE)
6. 5.6 AI pentest agents, fingerprinted and caught attacking us
7. 3.2 28,031 forged certs, one key, a 111x undercount
8. 1.6 A 2016 Cisco bug still leaks router logins on 41% of exposed PPTP
9. 1.9 Formal verification for the whole internet
10. 5.3 One malformed reply identifies a million routers
11. 6.1 79% of exploited exposure isn't in CISA KEV
12. 3.6 Three-quarters of the internet's TLS is TV boxes

Embargoed, and the strongest stories once disclosed: 1.3 DrayTek, 1.4 Cisco ASA, 1.8 Tecomat,
1.13 CODESYS, 1.18 Ericom, 1.19 emBridge.
