---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kernel-driver-load-by-non-root-user.html
---

# Kernel Driver Load by non-root User [prebuilt-rule-8-17-4-kernel-driver-load-by-non-root-user]

Detects the loading of a Linux kernel module by a non-root user through system calls. Threat actors may leverage Linux kernel modules to load a rootkit on a system providing them with complete control and the ability to hide from security products. As other rules monitor for the addition of Linux kernel modules through system utilities or .ko files, this rule covers the gap that evasive rootkits leverage by monitoring for kernel module additions on the lowest level through auditd_manager.

**Rule type**: eql

**Rule indices**:

* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4462]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kernel Driver Load by non-root User**

Kernel modules extend the functionality of the Linux kernel, allowing dynamic loading of drivers or features. Typically, only root users can load these modules due to their potential to alter system behavior. Adversaries may exploit this by loading malicious modules, such as rootkits, to gain control and evade detection. The detection rule identifies non-root users attempting to load modules, signaling potential unauthorized activity.

**Possible investigation steps**

* Review the alert details to identify the non-root user (user.id) involved in the kernel module loading attempt.
* Check the system logs and audit logs for any additional context around the time of the event, focusing on the specific system calls (init_module, finit_module) used.
* Investigate the source and legitimacy of the kernel module being loaded by examining the module’s file path and associated metadata.
* Assess the user’s recent activity and permissions to determine if there are any signs of privilege escalation or unauthorized access.
* Correlate this event with other security alerts or anomalies on the same host to identify potential patterns of malicious behavior.
* Verify the integrity and security posture of the affected system by running a comprehensive malware and rootkit scan.

**False positive analysis**

* Legitimate software or system utilities may occasionally load kernel modules as part of their normal operation. Identify these applications and verify their behavior to ensure they are not malicious.
* Development environments or testing scenarios might involve non-root users loading kernel modules for legitimate purposes. Consider creating exceptions for these specific users or processes after thorough validation.
* Some system management tools or scripts executed by non-root users might trigger this rule. Review these tools and, if deemed safe, add them to an exception list to prevent unnecessary alerts.
* In environments where non-root users are granted specific permissions to load kernel modules, ensure these permissions are documented and monitored. Adjust the rule to exclude these known and authorized activities.
* Regularly review and update the list of exceptions to ensure that only verified and non-threatening behaviors are excluded, maintaining the integrity of the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Terminate any suspicious processes associated with the non-root user attempting to load the kernel module to halt any ongoing malicious activity.
* Conduct a thorough review of the loaded kernel modules on the affected system to identify and remove any unauthorized or malicious modules.
* Reset credentials and review permissions for the non-root user involved in the alert to prevent further unauthorized actions.
* Escalate the incident to the security operations team for a deeper forensic analysis to determine the scope of the compromise and identify any additional affected systems.
* Implement enhanced monitoring and logging for kernel module loading activities across all systems to detect similar threats in the future.
* Review and update security policies to ensure that only authorized users have the necessary permissions to load kernel modules, reducing the risk of unauthorized access.


## Setup [_setup_1305]

**Setup**

This rule requires data coming in from Auditd Manager.

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" on a Linux System:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration:  — "-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules"  — "-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules"


## Rule query [_rule_query_5454]

```js
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module") and user.id != "0"
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



