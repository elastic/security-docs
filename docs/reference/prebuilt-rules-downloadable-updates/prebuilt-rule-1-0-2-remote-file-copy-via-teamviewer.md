---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-remote-file-copy-via-teamviewer.html
---

# Remote File Copy via TeamViewer [prebuilt-rule-1-0-2-remote-file-copy-via-teamviewer]

Identifies an executable or script file remotely downloaded via a TeamViewer transfer session.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.html](https://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1507]

## Triage and analysis

## Investigating Remote File Copy via TeamViewer

Attackers commonly transfer tooling or malware from external systems into a compromised environment using the command
and control channel. However, they can also abuse legitimate utilities to drop these files.

TeamViewer is a remote access and remote control tool used by helpdesks and system administrators to perform various
support activities. It is also frequently used by attackers and scammers to deploy malware interactively and other
malicious activities. This rule looks for the TeamViewer process creating files with suspicious extensions.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Contact the user to gather information about who and why was conducting the remote access.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check whether the company uses TeamViewer for the support activities and if there is a support ticket related to this
access.
- Retrieve the file and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the company relies on TeamViewer to conduct
remote access and the triage has not identified suspicious or malicious files.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the IoCs identified.
- Remove and block malicious artifacts identified on the triage.
- Disable the involved accounts, or restrict their ability to log on remotely.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1742]

```js
file where event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Technique:

    * Name: Remote Access Software
    * ID: T1219
    * Reference URL: [https://attack.mitre.org/techniques/T1219/](https://attack.mitre.org/techniques/T1219/)



