---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/code-signing-policy-modification-through-registry.html
---

# Code Signing Policy Modification Through Registry [code-signing-policy-modification-through-registry]

Identifies attempts to disable the code signing policy through the registry. Code signing provides authenticity on a program, and grants the user with the ability to check whether the program has been tampered with. By allowing the execution of unsigned or self-signed code, threat actors can craft and execute malicious code.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_222]

**Triage and analysis**

**Investigating Code Signing Policy Modification Through Registry**

Microsoft created the Windows Driver Signature Enforcement (DSE) security feature to prevent drivers with invalid signatures from loading and executing into the kernel (ring 0). DSE aims to protect systems by blocking attackers from loading malicious drivers on targets.

This protection is essential for maintaining system security. However, attackers or administrators can disable DSE and load untrusted drivers, which can put the system at risk. Therefore, it’s important to keep this feature enabled and only load drivers from trusted sources to ensure system integrity and security.

This rule identifies registry modifications that can disable DSE.

[TBC: QUOTE]
**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Use Osquery and endpoint driver events (`event.category = "driver"`) to investigate if suspicious drivers were loaded into the system after the registry was modified.
* !{osquery{"label":"Osquery - Retrieve All Non-Microsoft Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE NOT (provider == \"Microsoft\" AND signed == \"1\")\n"}}
* !{osquery{"label":"Osquery - Retrieve All Unsigned Drivers with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, class, description, directory, image,\nissuer_name, manufacturer, service, signed, subject_name FROM drivers JOIN authenticode ON drivers.image =\nauthenticode.path JOIN hash ON drivers.image = hash.path WHERE signed == \"0\"\n"}}
* Identify the driver’s `Device Name` and `Service Name`.
* Check for alerts from the rules specified in the `Related Rules` section.

**False positive analysis**

* This activity should not happen legitimately. The security team should address any potential benign true positive (B-TP), as this configuration can put the user and the domain at risk.

**Related Rules**

* First Time Seen Driver Loaded - df0fd41e-5590-4965-ad5e-cd079ec22fa9
* Untrusted Driver Loaded - d8ab1ec1-feeb-48b9-89e7-c12e189448aa
* Code Signing Policy Modification Through Built-in tools - b43570de-a908-4f7f-8bdb-b2df6ffd8c80

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Disable and uninstall all suspicious drivers found in the system. This can be done via Device Manager. (Note that this step may require you to boot the system into Safe Mode.)
* Remove the related services and registry keys found in the system. Note that the service will probably not stop if the driver is still installed.
* This can be done via PowerShell `Remove-Service` cmdlet.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Remove and block malicious artifacts identified during triage.
* Ensure that the Driver Signature Enforcement is enabled on the system.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_230]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.value: "BehaviorOnFailedVerify" and registry.data.strings : ("0", "0x00000000", "1", "0x00000001")

  /*
    Full registry key path omitted due to data source variations:
    "HKEY_USERS\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify"
  */
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Sub-technique:

    * Name: Code Signing Policy Modification
    * ID: T1553.006
    * Reference URL: [https://attack.mitre.org/techniques/T1553/006/](https://attack.mitre.org/techniques/T1553/006/)



