---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-time-seen-driver-loaded.html
---

# First Time Seen Driver Loaded [first-time-seen-driver-loaded]

Identifies the load of a driver with an original file name and signature values that were observed for the first time during the last 30 days. This rule type can help baseline drivers installation within your environment.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks](https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Persistence
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_346]

**Triage and analysis**

**Investigating First Time Seen Driver Loaded**

A driver is a software component that allows the operating system to communicate with hardware devices. It works at a high privilege level, the kernel level, having high control over the system’s security and stability.

Attackers may exploit known good but vulnerable drivers to execute code in their context because once an attacker can execute code in the kernel, security tools can no longer effectively protect the host. They can leverage these drivers to tamper, bypass and terminate security software, elevate privileges, create persistence mechanisms, and disable operating system protections and monitoring features. Attackers were seen in the wild conducting these actions before acting on their objectives, such as ransomware.

Read the complete research on "Stopping Vulnerable Driver Attacks" done by Elastic Security Labs [here](https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks).

This rule identifies the load of a driver with an original file name and signature values observed for the first time during the last 30 days. This rule type can help baseline drivers installation within your environment.

[TBC: QUOTE]
**Possible investigation steps**

* Examine the driver loaded to identify potentially suspicious characteristics. The following actions can help you gain context:
* Identify the path that the driver was loaded from. If using Elastic Defend, this information can be found in the `dll.path` field.
* Examine the digital signature of the driver, and check if it’s valid.
* Examine the creation and modification timestamps of the file:
* On Elastic Defend, those can be found in the `dll.Ext.relative_file_creation_time` and `"dll.Ext.relative_file_name_modify_time"` fields, with the values being seconds.
* Search for file creation events sharing the same file name as the `dll.name` field and identify the process responsible for the operation.
* Investigate any other abnormal behavior by the subject process, such as network connections, registry or file modifications, and any spawned child processes.
* Use the driver SHA-256 (`dll.hash.sha256` field) hash value to search for the existence and reputation in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* Use Osquery to investigate the drivers loaded into the system.
* !{osquery{"label":"Osquery - Retrieve All Non-Microsoft Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE NOT (provider == \"Microsoft\" AND signed == \"1\")\n"}}
* !{osquery{"label":"Osquery - Retrieve All Unsigned Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE signed == \"0\"\n"}}
* Identify the driver’s `Device Name` and `Service Name`.
* Check for alerts from the rules specified in the `Related Rules` section.

**False positive analysis**

* Matches derived from these rules are not inherently malicious. The security team should investigate them to ensure they are legitimate and needed, then include them in an allowlist only if required. The security team should address any vulnerable driver installation as it can put the user and the domain at risk.

**Related Rules**

* Untrusted Driver Loaded - d8ab1ec1-feeb-48b9-89e7-c12e189448aa
* Code Signing Policy Modification Through Registry - da7733b1-fe08-487e-b536-0a04c6d8b0cd
* Code Signing Policy Modification Through Built-in tools - b43570de-a908-4f7f-8bdb-b2df6ffd8c80

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Disable and uninstall all suspicious drivers found in the system. This can be done via Device Manager. (Note that this step may require you to boot the system into Safe Mode)
* Remove the related services and registry keys found in the system. Note that the service will probably not stop if the driver is still installed.
* This can be done via PowerShell `Remove-Service` cmdlet.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Ensure that the Driver Signature Enforcement is enabled on the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_378]

```js
event.category:"driver" and host.os.type:windows and event.action:"load"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



