---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-memory-threat-prevented-elastic-defend.html
---

# Memory Threat - Prevented- Elastic Defend [prebuilt-rule-8-17-2-memory-threat-prevented-elastic-defend]

Generates a detection alert each time an Elastic Defend alert for memory signatures are received. Enabling this rule allows you to immediately begin investigating your Endpoint memory signature alerts. This rule identifies Elastic Defend memory signature preventions only, and does not include detection only alerts.

**Rule type**: query

**Rule indices**:

* logs-endpoint.alerts-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**:

* [https://github.com/elastic/protections-artifacts/tree/main/yara](https://github.com/elastic/protections-artifacts/tree/main/yara)
* [https://docs.elastic.co/en/integrations/endpoint](https://docs.elastic.co/en/integrations/endpoint)

**Tags**:

* Data Source: Elastic Defend
* Tactic: Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3896]

**Triage and analysis**

**Investigating Memory Threat Alerts**

Elastic Endpoint’s memory threat protection adds a layer of coverage for advanced attacks which avoid the traditional approach of writing payloads to disk. Instead, the malicious code runs only in-memory, an effective technique for evading legacy security products. There are currently two sub-categories of memory threat protection.

The first category is referred to as memory signatures and is available on all supported OS. It operates by periodically scanning process executable memory regions based on their activity to identify and terminate known bad malware.

The second category is referred to as shellcode thread and is unique to Windows endpoints today. A common technique of in-memory malware is to load the payload in a memory region not backed by a file on disk and create a thread to execute it.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts :
* For shellcode alerts, the key for bucketing alerts is stored in the `Memory_protection.unique_key_v1` field.
* For Memory signature alerts, bucket based on the signatures which match `rule.name`.
* Examine the following fields if there are any matches on known Yara signatures:
* `process.Ext.memory_region.malware_signature.all_names`
* `Target.process.Ext.memory_region.malware_signature.all_names`
* `process.Ext.memory_region.malware_signature.primary.signature.name`
* Review the memory region strings for any suspicious or unique keywords captured in `process.Ext.memory_region.strings` and `Target.process.Ext.memory_region.strings`.
* For signature matches review the `process.Ext.memory_region.malware_signature.primary.matches` and `process.Ext.memory_region.malware_signature.secondary.matches` to understand which keywords or byte sequences matched on the memory Yara signature.
* For shellcode alerts, check the field `Memory_protection.self_injection` value, if it’s false it means it’s a remote shellcode injection and you need to review the Target process details like `Target.process.executable` fields.
* Even if the acting process is signed, review any unsigned or suspicious loaded libraries (adversaries may use `DLL Side-Loading`) captured in:
* `process.thread.Ext.call_stack.module_path`
* `process.Ext.dll.path and process.Ext.dll.hash.sha256`
* `Target.process.Ext.dll.hash.sha256`
* `Target.process.Ext.dll.path`
* If you have access to VirusTotal of similar services, you can also perform vGrep searches to look for files with bytes matching on `process.thread.Ext.start_address_bytes` or `Target.process.thread.Ext.start_address_bytes`.
* Investigate any abnormal behavior by the subject process, such as network connections, registry or file modifications, and any spawned child processes.

**False positive analysis**

* False positives may include Yara signature matches on generic keywords or some third party software performing code injection (often all involved files are signed and by the same vendor).

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Implement Elastic Endpoint Security to detect and prevent further post exploitation activities in the environment.
* Contain the affected system by isolating it from the network to prevent further spread of the attack.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Restore the affected system to its operational state by applying any necessary patches, updates, or configuration changes.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_773]

**Setup**

**Elastic Defend Alerts**

This rule is designed to capture specific alerts generated by Elastic Defend.

To capture all the Elastic Defend alerts, it is recommended to use all of the Elastic Defend feature-specific protection rules:

Behavior - Detected - Elastic Defend (UUID: 0f615fe4-eaa2-11ee-ae33-f661ea17fbce) Behavior - Prevented - Elastic Defend (UUID: eb804972-ea34-11ee-a417-f661ea17fbce) Malicious File - Detected - Elastic Defend (UUID: f2c3caa6-ea34-11ee-a417-f661ea17fbce) Malicious File - Prevented - Elastic Defend (UUID: f87e6122-ea34-11ee-a417-f661ea17fbce) Memory Threat - Detected - Elastic Defend (UUID: 017de1e4-ea35-11ee-a417-f661ea17fbce) Memory Threat - Prevented - Elastic Defend (UUID: 06f3a26c-ea35-11ee-a417-f661ea17fbce) Ransomware - Detected - Elastic Defend (UUID: 0c74cd7e-ea35-11ee-a417-f661ea17fbce) Ransomware - Prevented - Elastic Defend (UUID: 10f3d520-ea35-11ee-a417-f661ea17fbce)

To avoid generating duplicate alerts, you should enable either all feature-specific protection rules or the Endpoint Security (Elastic Defend) rule (UUID: 9a1a2dae-0b5f-4c3d-8305-a268d404c306).

**Additional notes**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_4791]

```js
event.kind : alert and event.code : (memory_signature or shellcode_thread) and event.type : denied and event.outcome : success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Technique:

    * Name: Reflective Code Loading
    * ID: T1620
    * Reference URL: [https://attack.mitre.org/techniques/T1620/](https://attack.mitre.org/techniques/T1620/)



