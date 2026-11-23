# Publication rules

Check every draft against this list before review.

## Never publish

- **Host IPs** of anything in this pack. This includes leakers, honeypots, replay hosts, the
  NetBIOS confirmation host and the hosts used to re-probe DrayTek. Aggregate by country or ASN only.
- **Real leaked bytes from internet hosts.**
  - DrayTek, coturn, PPTP and IKE leaks may contain other people's traffic: login prompts, typed
    usernames, RADIUS AVPs, VPN plaintext, peers' IP addresses.
  - Show **lab or synthetic bytes only**.
  - The IKE artifact's annotated dump redacts the responder address. Re-check any third-party
    address strings in it before reuse.
- **The DrayTek 4.x firmware key** and any decryption recipe.
- **The ASA libc-distance constants** and the pointer-to-libc measurement recipe (finding 7).
- **Unconfirmed security claims about the `taurus` shell** (tcp/6001). Confirm first, consider
  disclosure to the ISP or vendor, and never name or enumerate hosts.
- **Named customers or organisations** found in leaking populations, or the vendors whose customers
  they are.

## Wording

- **DrayTek:** "exposes internal tunnel addressing and destinations". **Never** "unmasks the client's
  public IP"; the outer header is stripped before the buffer.
- **coturn pcap:** the 508-byte example is **seeded through gdb**. Label it synthetic. The natural lab
  run shows an empty reason.
- **BENIGNCERTAIN:**
  - Say "devices that respond the way CVE-2016-6415 describes" or "likely unpatched".
  - Version data cannot show which releases leak.
  - The trigger relationship comes from comparison with Metasploit, not from testing a patched box.
  - 9 leakers are not IOS; Cisco says ASA is not affected (probably NAT).
- **Cisco ASA (finding 7):**
  - Say "stack over-read" and "discloses 28 bytes of stack, including a stack pointer". Not
    "uninitialised memory"; the debugger showed a copy from the wrong address.
  - No key material was seen. The canary-like field bytes are unproven; do not claim a canary leak.
  - FTD is affected on static evidence only; say so.
  - It is not BENIGNCERTAIN; keep the two apart.
- **Exposure counts are floors** where passive zeros were shown to leak on re-probe (DrayTek). Say so.
- **Customer-facing copy:**
  - No "AIRF" (say "detection rules").
  - No "IP Intel" or "IP intelligence".
  - No JA4TS.
  - Say "Target Intel" for the product.
- **Darklantern:** do not call cloud-hosted echoers "honeypot sensors" as fact; it is an inference.
- Present **rediscoveries** as rediscoveries, and credit the original finders: Dragos/Reid Wightman
  for ABB, Cisco for its advisories, the Metasploit module authors.
- **Clean negatives** are "clean for the checks we ran", never "not vulnerable".

## Disclosure state

Re-check each item before publishing.

| Item | State on 2026-11-17 | What publishing needs |
|---|---|---|
| coturn | CVE-2026-104074 published, fixed in 4.11.0 | Nothing |
| DrayTek OpenVPN | Reported 2026-10-22; V2865 beta fix verified; **no CVE** | A CVE id plus DrayTek's advisory and fixed versions |
| BENIGNCERTAIN | Known CVE; the CNA question on a new CVE was not recorded; airf-rules #1520 open | The team's CNA decision; the rule deployed |
| PPTP Cisco | Known CVE, no vendor fix | Nothing; describe content classes only |
| ABB AC500 | Known CVE, fixed in 2.5.3 | Nothing |
| Cisco ASA / FTD INVALID-COOKIE (finding 7) | Lab-confirmed 2026-11-23; **not reported, no CVE** | A PSIRT report, a CVE id and Cisco's fixed versions |
| `taurus` tcp/6001 | Unconfirmed | Confirmation and a disclosure decision |
| CVE-2026-109438 (3proxy, teammate) | Not in our history | The teammate's write-up |

## Active probing

Recon and confirmation probes run from **sprox-03**, not a laptop. For the Org3 and Org4 scopes they
send the User-Agent "NCSC Enhanced Scanning". Some October A/B probing ran from the user's own
machine. Don't describe that as how we normally work.

Do not repeat or fuzz the Juniper SSR probes: malformed packets cause HMAC-failure events on
third-party routers.
