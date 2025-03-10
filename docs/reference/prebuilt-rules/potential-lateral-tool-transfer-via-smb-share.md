---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-lateral-tool-transfer-via-smb-share.html
---

# Potential Lateral Tool Transfer via SMB Share [potential-lateral-tool-transfer-via-smb-share]

Identifies the creation or change of a Windows executable file over network shares. Adversaries may transfer tools or other files between systems in a compromised environment.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* logs-endpoint.events.network-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper](https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper)
* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_698]

**Triage and analysis**

**Investigating Potential Lateral Tool Transfer via SMB Share**

Adversaries can use network shares to host tooling to support the compromise of other hosts in the environment. These tools can include discovery utilities, credential dumpers, malware, etc. Attackers can also leverage file shares that employees frequently access to host malicious files to gain a foothold in other machines.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Retrieve the created file and determine if it is malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* File and registry access, modification, and creation activities.
* Service creation and launch activities.
* Scheduled task creation.
* Use the PowerShell `Get-FileHash` cmdlet to get the files' SHA-256 hash values.
* Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* This activity can happen legitimately. Consider adding exceptions if it is expected and noisy in your environment.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Review the privileges needed to write to the network share and restrict write access as needed.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_738]

```js
sequence by host.id with maxspan=30s
  [network where host.os.type == "windows" and event.type == "start" and process.pid == 4 and destination.port == 445 and
   network.direction : ("incoming", "ingress") and
   network.transport == "tcp" and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by process.entity_id
  /* add more executable extensions here if they are not noisy in your environment */
  [file where host.os.type == "windows" and event.type in ("creation", "change") and process.pid == 4 and
   (file.Ext.header_bytes : "4d5a*" or file.extension : ("exe", "scr", "pif", "com", "dll"))] by process.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)

* Technique:

    * Name: Lateral Tool Transfer
    * ID: T1570
    * Reference URL: [https://attack.mitre.org/techniques/T1570/](https://attack.mitre.org/techniques/T1570/)



