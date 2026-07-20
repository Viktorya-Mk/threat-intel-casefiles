**TLP:CLEAR** | Based on open-source reporting | Prepared for portfolio reference

# APT38: Attack Lifecycle Analysis

## Key Judgments

- We assess with high confidence that APT38 is a North Korean state-sponsored group whose financial theft operations function as regime revenue generation, not ordinary cybercrime.
- We assess with moderate confidence that the group's long dwell times reflect a deliberate choice to treat each intrusion as an internal reconnaissance project before any transaction fraud is attempted.
- We assess with high confidence that the group's destructive endgame, including disk wiping and mass service outages, is intended to slow investigation and cover the preceding theft rather than to punish the victim.

## Scope and Sources

This report reconstructs the APT38 attack lifecycle using FireEye's 2018 report *APT38: Un-usual Suspects*, cross-referenced against the U.S. Department of Justice complaint against Park Jin Hyok. Technique identifiers follow MITRE ATT&CK Enterprise naming. All findings are drawn from public reporting.

## Actor Profile

| Field | Detail |
|---|---|
| Sponsor | North Korea, Reconnaissance General Bureau, 6th Technical Bureau, Lab 110 |
| Motivation | Financial theft to fund the regime under sanctions pressure |
| Active since | At least February 2014 |
| Scale | 16 or more organizations across 13 or more countries, over $1.1 billion attempted |
| Related activity | Shares developers and malware code with TEMP.Hermit and the broader Lazarus cluster |
| Dwell time | Averages 155 days, with one case reaching 678 days |

APT38 treats a bank compromise as an intelligence operation. The group studies internal systems for months before touching any transaction. This patience shows up directly in its SWIFT-specific malware, which is built for a specific victim's environment rather than reused unchanged.

## Attack Lifecycle

Each stage below names the technique and explains the reasoning behind it. Technique IDs follow MITRE ATT&CK.

### Reconnaissance
APT38 identifies which third-party vendor manages a target bank's SWIFT connection before attacking the bank itself (T1591, Gather Victim Org Information). Operators also build employee contact lists through LinkedIn, in one case gathering 37 email addresses at a single bank (T1589.002, Gather Victim Identity Information: Email Addresses). This groundwork means the eventual phishing attempt reaches someone plausibly tied to SWIFT operations instead of a random employee.

### Initial Access
The group has used three main entry methods. A watering hole placed on the website of a Polish financial regulator, chained to other financial and cryptocurrency sites, harvested visitors across an entire sector at once (T1189, Drive-by Compromise). An unpatched Apache Struts2 server gave direct access to Linux infrastructure at one victim (T1190, Exploit Public-Facing Application). Résumé-themed phishing lures were also used, with lower confidence in direct attribution, and appear to share development resources with the sibling group TEMP.Hermit (T1566, Phishing).

### Execution and Foothold
Backdoors were staged one at a time rather than deployed as a single kit. NESTEGG, a memory-only backdoor, KEYLIME, a keylogger, and CHEESETRAY, a proxy-aware backdoor, were each introduced as the group's understanding of the environment grew (T1105, Ingress Tool Transfer). At least nine of the group's 26 known malware families use commercial packers such as Themida or VMProtect (T1027.002, Software Packing), applied selectively rather than across the whole toolkit.

### Discovery
MAPMAKER lists active local TCP connections instead of scanning the network for open ports (T1049, System Network Connections Discovery). This is a quieter choice, suited to an operator planning to stay resident for months. Sysmon, a legitimate Sysinternals tool, was installed to observe which processes and users touch SWIFT systems specifically (T1057, Process Discovery).

### Credential Access
KEYLIME captures keystrokes at SWIFT-adjacent workstations rather than dumping credentials from memory (T1056.001, Input Capture: Keylogging). SWIFT operator access is often tied to hardware tokens or session-based authentication, which a memory dump would not reliably capture, so logging input directly is the more reliable option.

### Lateral Movement and Command and Control
NACHOCHEESE relays commands between an active-mode CHEESETRAY backdoor on a SWIFT workstation and a passive-mode CHEESETRAY listener on the segmented SWIFT Alliance server, reached over port 8443 (T1090.001, Proxy: Internal Proxy). Passive backdoors are reserved for the most segmented systems. The group avoids initiating outbound connections from the host that matters most, which lowers the odds that egress monitoring on that segment ever fires. Custom binary protocols on non-standard ports round out the group's command and control (T1571, Non-Standard Port; T1573, Encrypted Channel).

### Collection and Financial Objective
DYEPACK edits SWIFT transaction records directly inside the Alliance Access Oracle database (T1565.001, Data Manipulation: Stored Data Manipulation). A deleted record draws attention. A falsified one does not, which is why the group edits rather than removes. A variant called DYEPACK.FOX was built specifically for one victim that reviewed SWIFT messages through Foxit PDF Reader instead of printed copies, showing the toolkit is adapted per target.

### Defense Evasion
The group replaces the legitimate SWIFT print utility `nroff.exe` with a DYEPACK component and matches existing file-naming conventions on each host (T1036.005, Masquerading: Match Legitimate Name). Two separate tools handle anti-forensics: SCRUBBRUSH clears event logs and prefetch files, and CLOSESHAVE securely deletes files (T1070.001 and T1070.004, Indicator Removal). Keeping these as separate tools means one being flagged by antivirus does not remove the group's entire cleanup capability. APT38 has also dropped a DARKCOMET sample pointing to a legitimate African bank's infrastructure and planted mistranslated Russian strings in NACHOCHEESE, both intended to send investigators toward the wrong attribution (T1036, Masquerading).

### Impact
BOOTWRECK destroys master boot record sectors and forces a reboot into failure, which is faster to run across thousands of hosts than a full disk wipe and just as disruptive (T1561.002, Disk Wipe: Disk Structure Wipe). HERMES ransomware has also been deployed in a misconfigured state that could not collect payment, indicating its role was evidence destruction rather than monetization (T1486, Data Encrypted for Impact). One incident took roughly 10,000 workstations and servers offline, including phone service. That scale of disruption gives the preceding SWIFT fraud cover while it is investigated (T1489, Service Stop).

## Technique Mapping

```json
{
  "actor": "APT38",
  "attribution": "North Korea, RGB Lab 110",
  "stages": [
    { "tactic": "reconnaissance", "techniques": ["T1591", "T1589.002"] },
    { "tactic": "initial-access", "techniques": ["T1189", "T1190", "T1566"] },
    { "tactic": "execution", "techniques": ["T1105"] },
    { "tactic": "defense-evasion", "techniques": ["T1027.002", "T1036.005", "T1070.001", "T1070.004", "T1036"] },
    { "tactic": "discovery", "techniques": ["T1049", "T1057"] },
    { "tactic": "credential-access", "techniques": ["T1056.001"] },
    { "tactic": "lateral-movement", "techniques": ["T1021"] },
    { "tactic": "command-and-control", "techniques": ["T1090.001", "T1571", "T1573"] },
    { "tactic": "collection", "techniques": ["T1565.001"] },
    { "tactic": "impact", "techniques": ["T1561.002", "T1486", "T1489"] }
  ],
  "notable_tools": ["NESTEGG", "KEYLIME", "CHEESETRAY", "MAPMAKER", "DYEPACK", "DYEPACK.FOX", "BOOTWRECK", "HERMES", "SCRUBBRUSH", "CLOSESHAVE", "NACHOCHEESE"]
}
```

T1561.002 and T1489 sit under the ATT&CK Impact tactic. T1565.001 sits under Collection. The fraudulent transaction itself is the business objective, but the technique ATT&CK models is the data manipulation that hides it.

## Defensive Actions

| Technique | Recommended action |
|---|---|
| T1565.001, DYEPACK | Check local SWIFT message stores against the network-side gateway log on a schedule. Alert on Oracle CLI activity against the Alliance Access schema from any account other than the expected database administrator. |
| T1090.001, passive backdoor on SWIFT segment | SWIFT-adjacent hosts should have no listening ports beyond documented Alliance Access services. Treat any new listener as a high-priority alert. |
| T1561.002, BOOTWRECK | Apply firmware-level write blocking on boot sectors for SWIFT operator workstations. Keep offline, immutable backups so a mass-wipe event cannot also destroy the recovery path. |
| T1049, MAPMAKER | Baseline expected local connection enumeration behavior. MAPMAKER writes its output to a temp file, which is detectable if endpoint logging captures that write. |
| Long dwell time | Assume presence rather than prevention is the realistic posture for SWIFT-connected environments. Segment general IT from SWIFT infrastructure, and audit firewall rule changes on a short cycle, since the group repeatedly creates rules to enable inbound backdoor access. |

## Sources

- FireEye, *APT38: Un-usual Suspects*, 2018.
- U.S. Department of Justice, criminal complaint against Park Jin Hyok, unsealed September 6, 2018.
