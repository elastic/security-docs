---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-remote-file-download-via-desktopimgdownldr-utility.html
---

# Remote File Download via Desktopimgdownldr Utility [prebuilt-rule-8-3-2-remote-file-download-via-desktopimgdownldr-utility]

Identifies the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.

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

* [https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/](https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2405]

## Triage and analysis

## Investigating Remote File Download via Desktopimgdownldr Utility

Attackers commonly transfer tooling or malware from external systems into a compromised environment using the command
and control channel. However, they can also abuse signed utilities to drop these files.

The `Desktopimgdownldr.exe` utility is used to to configure lockscreen/desktop image, and can be abused with the
`lockscreenurl` argument to download remote files and tools, this rule looks for this behavior.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
- Check the reputation of the domain or IP address used to host the downloaded file or if the user downloaded the file
from an internal system.
- Retrieve the file and determine if it is malicious:
  - Identify the file type.
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unusual but can be done by administrators. Benign true positives (B-TPs) can be added as exceptions
if necessary.
- Analysts can dismiss the alert if the downloaded file is a legitimate image.

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
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2771]

```js
process where event.type == "start" and
  (process.name : "desktopimgdownldr.exe" or process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
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



