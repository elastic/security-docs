---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kernel-driver-load.html
---

# Kernel Driver Load [prebuilt-rule-8-17-4-kernel-driver-load]

Detects the loading of a Linux kernel module through system calls. Threat actors may leverage Linux kernel modules to load a rootkit on a system providing them with complete control and the ability to hide from security products. As other rules monitor for the addition of Linux kernel modules through system utilities or .ko files, this rule covers the gap that evasive rootkits leverage by monitoring for kernel module additions on the lowest level through auditd_manager.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Auditd Manager
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

## Investigation guide [_investigation_guide_4461]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Driver Load**

Kernel modules extend the functionality of the Linux kernel, allowing dynamic loading of drivers and other components. Adversaries exploit this by loading malicious modules, or rootkits, to gain stealthy control over systems. The *Kernel Driver Load* detection rule leverages auditd to monitor system calls like `init_module`, identifying unauthorized module loads indicative of potential rootkit activity, thus enhancing threat detection and system integrity.

**Possible investigation steps**

* Review the alert details to identify the specific host where the kernel module was loaded, focusing on the host.os.type field to confirm it is a Linux system.
* Examine the event.action field to verify that the action was indeed "loaded-kernel-module" and check the auditd.data.syscall field for the specific system call used, either "init_module" or "finit_module".
* Investigate the timeline of events on the affected host around the time of the alert to identify any suspicious activities or changes, such as new user accounts, unexpected network connections, or file modifications.
* Check the system logs and audit logs on the affected host for any additional context or anomalies that coincide with the module load event.
* Identify the source and legitimacy of the loaded kernel module by examining the module’s file path, signature, and associated metadata, if available.
* Assess the potential impact and scope of the incident by determining if similar alerts have been triggered on other hosts within the environment, indicating a broader campaign or attack.

**False positive analysis**

* Legitimate kernel module updates or installations can trigger alerts. Regularly scheduled updates or installations by trusted administrators should be documented and excluded from monitoring to reduce noise.
* System utilities that load kernel modules as part of their normal operation may cause false positives. Identify these utilities and create exceptions for their expected behavior.
* Automated configuration management tools that deploy or update kernel modules can generate alerts. Ensure these tools are recognized and their activities are whitelisted.
* Development environments where kernel modules are frequently compiled and tested may lead to frequent alerts. Exclude specific development hosts or processes from monitoring to avoid unnecessary alerts.
* Security software that loads kernel modules for protection purposes might be flagged. Verify and exclude these modules if they are from trusted vendors.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further malicious activity and lateral movement.
* Verify the legitimacy of the loaded kernel module by checking its source and integrity. If the module is unauthorized or suspicious, unload it using appropriate system commands.
* Conduct a thorough scan of the system using updated antivirus or anti-malware tools to identify and remove any additional malicious components or rootkits.
* Review and analyze system logs, especially those related to auditd, to identify any unauthorized access or changes made by the adversary. This can help in understanding the scope of the compromise.
* Restore the system from a known good backup if the integrity of the system is in question and if the malicious activity cannot be fully remediated.
* Implement stricter access controls and monitoring on kernel module loading activities to prevent unauthorized actions in the future. This may include restricting module loading to trusted users or processes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1304]

**Setup**

This rule requires the use of the `auditd_manager` integration. `Auditd_manager` is a tool designed to simplify and enhance the management of the audit subsystem in Linux systems. It provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system. The following steps should be executed in order to install and deploy `auditd_manager` on a Linux system.

```
Kibana -->
Management -->
Integrations -->
Auditd Manager -->
Add Auditd Manager
```

`Auditd_manager` subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from.

For this detection rule to trigger, the following additional audit rules are required to be added to the integration:

```
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
```

Add the newly installed `auditd manager` to an agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.


## Rule query [_rule_query_5453]

```js
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module")
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



