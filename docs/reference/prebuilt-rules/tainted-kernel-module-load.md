---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/tainted-kernel-module-load.html
---

# Tainted Kernel Module Load [tainted-kernel-module-load]

This rule monitors the syslog log file for messages related to instances of a tainted kernel module load. Rootkits often leverage kernel modules as their main defense evasion technique. Detecting tainted kernel module loads is crucial for ensuring system security and integrity, as malicious or unauthorized modules can compromise the kernel and lead to system vulnerabilities or unauthorized access.

**Rule type**: query

**Rule indices**:

* logs-system.syslog-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1071]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Tainted Kernel Module Load**

Kernel modules extend the functionality of the Linux kernel, allowing dynamic loading of code. While beneficial, they can be exploited by adversaries to introduce malicious code, bypassing security measures. Attackers may load unsigned or improperly signed modules, leading to a "tainted" kernel state. The detection rule identifies such events by monitoring syslog for specific error messages, signaling potential unauthorized module loads, thus aiding in early threat detection and system integrity maintenance.

**Possible investigation steps**

* Review the syslog entries around the time of the alert to gather additional context and identify any other suspicious activities or related events.
* Investigate the specific kernel module mentioned in the syslog message to determine its origin, legitimacy, and whether it is expected on the system.
* Check the system for any recent changes or installations that could have introduced the unsigned or improperly signed module, including software updates or new applications.
* Analyze the system for signs of compromise, such as unexpected network connections, unusual process activity, or unauthorized user accounts, which may indicate a broader security incident.
* Consult with system administrators or relevant personnel to verify if the module load was authorized or part of a legitimate operation, and document any findings or justifications provided.

**False positive analysis**

* Custom kernel modules: Organizations often use custom or proprietary kernel modules that may not be signed. These can trigger false positives. To manage this, maintain a list of known, trusted custom modules and create exceptions for them in the monitoring system.
* Outdated or unsupported hardware drivers: Some older hardware drivers may not have signed modules, leading to false positives. Regularly update drivers and, if necessary, exclude specific drivers that are known to be safe but unsigned.
* Development and testing environments: In environments where kernel module development occurs, unsigned modules may be loaded frequently. Implement separate monitoring rules or exceptions for these environments to avoid unnecessary alerts.
* Vendor-provided modules: Certain vendors may provide modules that are not signed. Verify the legitimacy of these modules with the vendor and consider excluding them if they are confirmed to be safe.
* Temporary testing modules: During troubleshooting or testing, temporary modules might be loaded without proper signing. Ensure these are removed after testing and consider temporary exceptions during the testing phase.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the attacker.
* Verify the integrity of the kernel and loaded modules by comparing them against known good versions or using a trusted baseline.
* Unload the suspicious kernel module if possible, and replace it with a verified, signed version to restore system integrity.
* Conduct a thorough forensic analysis of the affected system to identify any additional signs of compromise or persistence mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems are affected.
* Implement enhanced monitoring and logging for kernel module loads and other critical system activities to detect similar threats in the future.
* Review and update system and network access controls to ensure only authorized personnel can load kernel modules, reducing the risk of unauthorized changes.


## Setup [_setup_677]

**Setup**

This rule requires data coming in from one of the following integrations: - Filebeat

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat for the Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete Setup and Run Filebeat information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the Filebeat System Module to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_1126]

```js
host.os.type:linux and event.dataset:"system.syslog" and process.name:kernel and
message:"module verification failed: signature and/or required key missing - tainting kernel"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



