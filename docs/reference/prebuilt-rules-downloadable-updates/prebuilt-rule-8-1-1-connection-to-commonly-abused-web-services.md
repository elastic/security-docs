---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-connection-to-commonly-abused-web-services.html
---

# Connection to Commonly Abused Web Services [prebuilt-rule-8-1-1-connection-to-commonly-abused-web-services]

Adversaries may implement command and control (C2) communications that use common web services to hide their activity. This attack technique is typically targeted at an organization and uses web services common to the victim network, which allows the adversary to blend into legitimate traffic activity. These popular services are typically targeted since they have most likely been used before compromise, which helps malicious traffic blend in.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1712]

## Triage and analysis

## Investigating Connection to Commonly Abused Web Services

Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised
system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the
likelihood that hosts within a network are already communicating with them prior to a compromise.

This rule looks for processes outside known legitimate program locations communicating with a list of services that can
be abused for exfiltration or command and control.

### Possible investigation steps

- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Verify whether the digital signature exists in the executable.
- Identify the operation type (upload, download, tunneling, etc.).
- Retrieve the process executable and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This rule has a high chance to produce false positives because it detects communication with legitimate services. Noisy
false positives can be added as exceptions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_1986]

```js
network where network.protocol == "dns" and
    process.name != null and user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
    /* Add new WebSvc domains here */
    dns.question.name :
    (
        "raw.githubusercontent.*",
        "*.pastebin.*",
        "*drive.google.*",
        "*docs.live.*",
        "*api.dropboxapi.*",
        "*dropboxusercontent.*",
        "*onedrive.*",
        "*4shared.*",
        "*.file.io",
        "*filebin.net",
        "*slack-files.com",
        "*ghostbin.*",
        "*ngrok.*",
        "*portmap.*",
        "*serveo.net",
        "*localtunnel.me",
        "*pagekite.me",
        "*localxpose.io",
        "*notabug.org",
        "rawcdn.githack.*",
        "paste.nrecom.net",
        "zerobin.net",
        "controlc.com",
        "requestbin.net",
        "cdn.discordapp.com",
        "discordapp.com",
        "discord.com"
    ) and
    /* Insert noisy false positives here */
    not process.executable :
    (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\WWAHost.exe",
      "?:\\Windows\\System32\\smartscreen.exe",
      "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
      "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
      "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      "?:\\Windows\\system32\\mobsync.exe",
      "?:\\Windows\\SysWOW64\\mobsync.exe",
      "?:\\Users\\*\\AppData\\Local\\Discord\\app-*\\Discord.exe"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Web Service
    * ID: T1102
    * Reference URL: [https://attack.mitre.org/techniques/T1102/](https://attack.mitre.org/techniques/T1102/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Web Service
    * ID: T1567
    * Reference URL: [https://attack.mitre.org/techniques/T1567/](https://attack.mitre.org/techniques/T1567/)

* Sub-technique:

    * Name: Exfiltration to Code Repository
    * ID: T1567.001
    * Reference URL: [https://attack.mitre.org/techniques/T1567/001/](https://attack.mitre.org/techniques/T1567/001/)

* Sub-technique:

    * Name: Exfiltration to Cloud Storage
    * ID: T1567.002
    * Reference URL: [https://attack.mitre.org/techniques/T1567/002/](https://attack.mitre.org/techniques/T1567/002/)



