---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/untrusted-driver-loaded.html
---

# Untrusted Driver Loaded [untrusted-driver-loaded]

Identifies attempt to load an untrusted driver. Adversaries may modify code signing policies to enable execution of unsigned or self-signed code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/hfiref0x/TDL](https://github.com/hfiref0x/TDL)
* [https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1099]

**Triage and analysis**

**Investigating Untrusted Driver Loaded**

Microsoft created the Windows Driver Signature Enforcement (DSE) security feature to prevent drivers with invalid signatures from loading and executing into the kernel (ring 0). DSE aims to protect systems by blocking attackers from loading malicious drivers on targets.

This protection is essential for maintaining system security. However, attackers or administrators can disable DSE and load untrusted drivers, which can put the system at risk. Therefore, it’s important to keep this feature enabled and only load drivers from trusted sources to ensure system integrity and security.

This rule identifies an attempt to load an untrusted driver, which effectively means that DSE was disabled or bypassed. This can indicate that the system was compromised.

[TBC: QUOTE]
**Possible investigation steps**

* Examine the driver loaded to identify potentially suspicious characteristics. The following actions can help you gain context:
* Identify the path that the driver was loaded from. If you’re using Elastic Defend, path information can be found in the `dll.path` field.
* Examine the file creation and modification timestamps:
* On Elastic Defend, those can be found in the `dll.Ext.relative_file_creation_time` and `dll.Ext.relative_file_name_modify_time` fields. The values are in seconds.
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

* This activity should not happen legitimately. The security team should address any potential benign true positive (B-TP), as this configuration can put the user and the domain at risk.

**Related Rules**

* First Time Seen Driver Loaded - df0fd41e-5590-4965-ad5e-cd079ec22fa9
* Code Signing Policy Modification Through Registry - da7733b1-fe08-487e-b536-0a04c6d8b0cd
* Code Signing Policy Modification Through Built-in tools - b43570de-a908-4f7f-8bdb-b2df6ffd8c80

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Disable and uninstall all suspicious drivers found in the system. This can be done via Device Manager. (Note that this step may require you to boot the system into Safe Mode.)
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


## Rule query [_rule_query_1157]

```js
driver where host.os.type == "windows" and process.pid == 4 and
  dll.code_signature.trusted != true and
  not dll.code_signature.status : ("errorExpired", "errorRevoked", "errorCode_endpoint:*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)



