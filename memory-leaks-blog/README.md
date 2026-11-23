# Memory leaks and weird data in internet scan data: blog series planning pack

Internal planning material for a long-form write-up or a blog series. It covers what VulnCheck found
between early October and mid-November 2026 by hunting passively through our BigQuery scan data
with two agent skills:

- `.claude/skills/hunting-protocol-memory-leaks/` looks for uninitialised or stale bytes in protocol
  fields: bytes outside the field's grammar, tails after a NUL, echo fields that diverge from what we
  sent.
- `.claude/skills/hunting-weird-protocol-data/` looks for rare response shapes that repeat across
  unrelated hosts, then promotes the real ones to IOCs or product fingerprints.

Nothing here is ready to publish. The pack is kept on a branch so the facts, numbers and sources are
in one place when the posts get written. Collated 2026-11-17 (finding 7 added 2026-11-23) from Claude Code session history,
memory notes, hunt reports and the skills' own reference files.

## Files

| File | What it holds |
|---|---|
| [`findings.md`](findings.md) | Every finding: what, how it was found, numbers, verdict, outputs, sensitivities, blog angle |
| [`series-outline.md`](series-outline.md) | The proposed posts, their beats, figures and publication gates |
| [`methodology.md`](methodology.md) | How the hunts work, lessons, false leads, costs, table and column facts |
| [`publication-rules.md`](publication-rules.md) | What must never be published and the wording rules |
| [`sources.md`](sources.md) | Sessions, PRs, issues, artifacts, local file paths, open items |

## Headline results

| Finding | Kind | Scale | Status |
|---|---|---|---|
| coturn 4.10.0 ERROR-CODE reason-phrase stack leak | **New CVE: CVE-2026-104074** (VulnCheck as CNA) | 58 hosts at discovery, ~3% of error responders | Published CVE; AIRF rules live |
| DrayTek Vigor (DrayOS) OpenVPN UDP/1194 stale-ack leak | **New vuln, no CVE yet** | 106,227 hosts in 30 days (a floor) | Reported 2026-10-22; vendor fix verified on a V2865 beta; blog held for CVE |
| Cisco IOS IKEv1 NO-PROPOSAL-CHOSEN notify heap leak | Rediscovered **CVE-2016-6415** (BENIGNCERTAIN, KEV) | 10,876 IPs, 1-11 Nov | Detection merged; CVE attribution PR open |
| Cisco IOS PPTP SCCRP hostname leak | Rediscovered **CVE-2016-6398** (never fixed by Cisco) | 4,787 of 11,596 Cisco PPTP IPs | Skill regression positive |
| ABB AC500 V2 Modbus device-ID slack | Rediscovered **CVE-2025-7745** | 32 hosts | Rule makes it attributable |
| Teco Tecomat Modbus oversized-exception cross-connection leak | **New vuln, candidate CVE** | 29 hosts over 240 days (a floor) | Confirmed 2026-11-17; attributed 2026-11-18; draft advisory ready, vendor not yet contacted |
| Cisco ASA / FTD IKEv1 INVALID-COOKIE 28-byte stack over-read | **New vuln, no CVE yet** | ~4.9k IPs; 84-97% of IKEv1-answering ASAs | Root cause confirmed in the lab 2026-11-23 on 9.16, 9.22, 9.24; not reported to Cisco |
| OpenClaw AI gateways via mDNS | Product identified | 1,434 to 2,789 hosts; HTTP rule missed 98.9% | Rules merged |
| Webmin MiniServ UDP 10000 reply | Product identified, plus a rule bug in our own Webmin rules | 17.9k UDP; ~80k+ newly identified Webmin/Usermin | Rules merged |
| QNAP HBS 3 RTRR frame on tcp/8899 | Product identified via firmware teardown | 2,072 hosts | Rule merged |
| Our own probes and replay hosts | Scanner data-quality | Up to 63% of a table's rows | Fixes merged across #4704, #4896, #4937-#4947 |
| tcp/6001 `taurus: /$` open shell prompt | **Unconfirmed** possible security finding | 2,202 Android boxes, 99% one ISP | Needs active confirmation |

Your teammate found **CVE-2026-109438** (3proxy). Our session history only mentions it as one of
the CVEs on the `cpe:2.3:a:3proxy:3proxy` CPE, in a 2026-11-05 SOCKS5 fingerprinting session. There
are no details of how it was found. Add the story to `findings.md` once they supply it.

## Gaps in the record

- The coturn and Cisco PPTP discovery transcripts (2026-10-06 to 10-09) have been deleted. That part
  is rebuilt from session `b5badb55` (2026-10-16), which quoted them, plus memory notes and the
  skill's git history.
- The original sweep scratch outputs (`output_A_list.md`, `output_B_packages.md`, `hosts/*.txt`) are
  gone from `/private/tmp`. Numbers come from transcript text.
- The CNA team's decision on whether BENIGNCERTAIN needs a new CVE is not recorded.
