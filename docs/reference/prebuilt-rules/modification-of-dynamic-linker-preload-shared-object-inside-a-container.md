---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/modification-of-dynamic-linker-preload-shared-object-inside-a-container.html
---

# Modification of Dynamic Linker Preload Shared Object Inside A Container [modification-of-dynamic-linker-preload-shared-object-inside-a-container]

This rule detects the creation or modification of the dynamic linker preload shared object (ld.so.preload) inside a container. The Linux dynamic linker is used to load libraries needed by a program at runtime. Adversaries may hijack the dynamic linker by modifying the /etc/ld.so.preload file to point to malicious libraries. This behavior can be used to grant unauthorized access to system resources and has been used to evade detection of malicious processes in container environments.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/)
* [https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang/](https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang/)
* [https://sysdig.com/blog/threat-detection-aws-cloud-containers/](https://sysdig.com/blog/threat-detection-aws-cloud-containers/)

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_540]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification of Dynamic Linker Preload Shared Object Inside A Container**

The dynamic linker in Linux loads necessary libraries for programs at runtime, with the `ld.so.preload` file specifying libraries to load first. Adversaries exploit this by redirecting it to malicious libraries, gaining unauthorized access and evading detection. The detection rule identifies suspicious modifications to this file within containers, signaling potential hijacking attempts.

**Possible investigation steps**

* Review the alert details to confirm the file path involved is "/etc/ld.so.preload" and the event type is not "deletion", as specified in the query.
* Examine the container’s metadata and context to identify the specific container where the modification occurred, including container ID, image, and host details.
* Investigate recent changes to the "/etc/ld.so.preload" file within the container by checking the file’s modification history and identifying the user or process responsible for the change.
* Analyze the contents of the modified "/etc/ld.so.preload" file to determine if it references any suspicious or unauthorized libraries.
* Correlate the event with other security logs and alerts to identify any related suspicious activities or patterns, such as unauthorized access attempts or execution of unknown processes within the container.
* Assess the potential impact of the modification by evaluating the libraries listed in the preload file and their potential to grant unauthorized access or evade detection.
* Consider isolating the affected container to prevent further unauthorized access or malicious activity while the investigation is ongoing.

**False positive analysis**

* Routine system updates or maintenance activities may modify the ld.so.preload file. Users should verify if the changes coincide with scheduled updates and consider excluding these events if they are confirmed to be benign.
* Some containerized applications might legitimately modify the ld.so.preload file to optimize performance or load specific libraries. Users should identify these applications and create exceptions for their known behaviors to prevent false alerts.
* Automated configuration management tools might alter the ld.so.preload file as part of their normal operations. Users should review the tool’s activity logs and whitelist these actions if they are consistent with expected behavior.
* Development or testing environments often involve frequent changes to system files, including ld.so.preload. Users should differentiate between production and non-production environments and apply more lenient rules to the latter to reduce false positives.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or execution of malicious code. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the `/etc/ld.so.preload` file within the container to identify any unauthorized or malicious entries. Remove any entries that are not recognized or are confirmed to be malicious.
* Verify the integrity of the container’s base image and all installed libraries to ensure no other components have been tampered with. Rebuild the container from a trusted image if necessary.
* Implement monitoring and alerting for any future modifications to the `/etc/ld.so.preload` file across all containers to detect similar threats promptly.
* Review and tighten access controls and permissions for container environments to minimize the risk of unauthorized modifications to critical system files.
* Escalate the incident to the security operations team for further investigation and to determine if the threat has spread to other parts of the infrastructure.
* Document the incident, including the steps taken for containment and remediation, to improve response strategies and update incident response plans for future reference.


## Rule query [_rule_query_581]

```js
file where event.module== "cloud_defend" and event.type != "deletion" and file.path== "/etc/ld.so.preload"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



