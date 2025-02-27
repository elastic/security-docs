---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-remote-file-download-via-desktopimgdownldr-utility.html
---

# Remote File Download via Desktopimgdownldr Utility [prebuilt-rule-1-0-2-remote-file-download-via-desktopimgdownldr-utility]

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

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1502]

## Triage and analysis

## Investigating Remote File Download via Desktopimgdownldr Utility

Attackers commonly transfer tooling or malware from external systems into a compromised environment using the command
and control channel. However, they can also abuse signed utilities to drop these files.

The `Desktopimgdownldr.exe` utility is used to to configure lockscreen/desktop image, and can be abused with the
`lockscreenurl` argument to download remote files and tools, this rule looks for this behavior.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Determine if the activity is unique by validating if other machines in the organization have similar entries.
- Check the reputation of the domain or IP address used to host the downloaded file or if the user downloaded the file
from an internal system.
- Retrieve the file and determine if it is malicious:
  - Identify the file type.
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unusual but can be done by administrators. Benign true positives (B-TPs) can be added as exceptions
if necessary.
- Analysts can dismiss the alert if the downloaded file is a legitimate image.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the IoCs identified.
- Remove and block malicious artifacts identified on the triage.
- Disable the involved accounts, or restrict their ability to log on remotely.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Investigate the initial attack vector.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1737]

```js
process where event.type in ("start", "process_started") and
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



