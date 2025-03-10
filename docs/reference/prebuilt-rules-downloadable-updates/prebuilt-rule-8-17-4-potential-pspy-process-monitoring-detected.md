---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-pspy-process-monitoring-detected.html
---

# Potential Pspy Process Monitoring Detected [prebuilt-rule-8-17-4-potential-pspy-process-monitoring-detected]

This rule leverages auditd to monitor for processes scanning different processes within the /proc directory using the openat syscall. This is a strong indication for the usage of the pspy utility. Attackers may leverage the pspy process monitoring utility to monitor system processes without requiring root permissions, in order to find potential privilege escalation vectors.

**Rule type**: eql

**Rule indices**:

* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

**Tags**:

* Data Source: Auditd Manager
* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4377]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Pspy Process Monitoring Detected**

Auditd is a Linux auditing system that tracks system calls, providing insights into process activities. Adversaries exploit tools like pspy to monitor processes via the /proc directory, seeking privilege escalation opportunities without root access. The detection rule identifies suspicious openat syscalls targeting /proc, excluding benign processes, to flag potential misuse of pspy for process discovery.

**Possible investigation steps**

* Review the process details associated with the alert, focusing on the process.pid and process.name fields to identify the process attempting to access the /proc directory.
* Investigate the host.id to determine if this activity is isolated to a single host or part of a broader pattern across multiple systems.
* Examine the process tree and parent processes of the flagged process to understand how it was initiated and if it is part of a legitimate workflow or potentially malicious activity.
* Check for any recent changes or installations on the host that might explain the presence of a tool like pspy, such as new software installations or updates.
* Correlate the timing of the alert with any other suspicious activities or alerts on the same host to identify potential lateral movement or privilege escalation attempts.
* Verify if the process name is a known benign process that might have been mistakenly excluded from the query, ensuring that the exclusion list is up-to-date and accurate.

**False positive analysis**

* Frequent scanning by legitimate monitoring tools can trigger the rule. Identify and whitelist these tools by adding their process names to the exclusion list.
* System management scripts that regularly access the /proc directory may cause false positives. Review these scripts and exclude their process names if they are verified as non-threatening.
* Automated backup or security software that interacts with the /proc directory might be flagged. Confirm their legitimacy and add them to the exception list to prevent unnecessary alerts.
* Custom applications developed in-house that require access to the /proc directory for performance monitoring should be reviewed and excluded if they are deemed safe.
* Regularly update the exclusion list to reflect changes in legitimate software and tools used within the organization to minimize false positives.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes identified as using the pspy utility to halt further unauthorized process monitoring.
* Conduct a thorough review of the affected system’s /proc directory access logs to identify any other unauthorized access attempts or anomalies.
* Reset credentials and review permissions for any accounts that may have been compromised or used in the attack to prevent further unauthorized access.
* Apply patches and updates to the affected system to address any vulnerabilities that may have been exploited for privilege escalation.
* Enhance monitoring and logging on the affected host to detect any future attempts to access the /proc directory using similar methods.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.


## Setup [_setup_1224]

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

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration:  — "-w /proc/ -p r -k audit_proc"


## Rule query [_rule_query_5369]

```js
sequence by process.pid, host.id with maxspan=5s
  [file where host.os.type == "linux" and auditd.data.syscall == "openat" and file.path == "/proc" and
   auditd.data.a0 : ("ffffffffffffff9c", "ffffff9c") and auditd.data.a2 : ("80000", "88000") and
   not process.name in ("agentbeat", "packetbeat")
  ] with runs=10
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



