---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-privilege-escalation-via-cap-chown-cap-fowner-capabilities.html
---

# Privilege Escalation via CAP_CHOWN/CAP_FOWNER Capabilities [prebuilt-rule-8-17-4-privilege-escalation-via-cap-chown-cap-fowner-capabilities]

Identifies instances where a processes (granted CAP_CHOWN and/or CAP_FOWNER capabilities) is executed, after which the ownership of a suspicious file or binary is changed. In Linux, the CAP_CHOWN capability allows a process to change the owner of a file, while CAP_FOWNER permits it to bypass permission checks on operations that require file ownership (like reading, writing, and executing). Attackers may abuse these capabilities to obtain unauthorized access to files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* auditbeat-*
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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4538]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via CAP_CHOWN/CAP_FOWNER Capabilities**

In Linux, CAP_CHOWN and CAP_FOWNER are capabilities that allow processes to change file ownership and bypass file permission checks, respectively. Adversaries exploit these to gain unauthorized access to sensitive files, such as password or configuration files. The detection rule identifies suspicious processes with these capabilities that alter ownership of critical files, signaling potential privilege escalation attempts.

**Possible investigation steps**

* Review the process details, including process.name and process.command_line, to understand the context of the executed process and its intended function.
* Check the user.id associated with the process to determine if the process was executed by a non-root user, which could indicate unauthorized privilege escalation attempts.
* Investigate the file.path that had its ownership changed to assess the potential impact, focusing on critical files like /etc/passwd, /etc/shadow, /etc/sudoers, and /root/.ssh/*.
* Analyze the sequence of events by examining the host.id and process.pid to identify any related processes or activities that occurred within the maxspan=1s timeframe.
* Correlate the event with other logs or alerts from the same host to identify any patterns or additional suspicious activities that might indicate a broader attack or compromise.

**False positive analysis**

* System administration scripts or automated processes may legitimately use CAP_CHOWN or CAP_FOWNER capabilities to manage file permissions or ownership. Review and whitelist these processes if they are verified as non-malicious.
* Backup or restoration operations often require changing file ownership and permissions. Identify and exclude these operations from triggering alerts by specifying known backup tools or scripts.
* Software installation or update processes might alter file ownership as part of their normal operation. Monitor and exclude these processes if they are part of a trusted software management system.
* Development or testing environments may have scripts that modify file ownership for testing purposes. Ensure these environments are properly segmented and exclude known development scripts from detection.
* Custom user scripts that require elevated permissions for legitimate tasks should be reviewed and, if deemed safe, added to an exception list to prevent false positives.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified with CAP_CHOWN or CAP_FOWNER capabilities that are altering file ownership, especially those targeting critical files like /etc/passwd or /etc/shadow.
* Revert any unauthorized changes to file ownership or permissions on critical files to their original state to restore system integrity.
* Conduct a thorough review of user accounts and privileges on the affected system to identify and disable any unauthorized accounts or privilege escalations.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement additional monitoring on the affected host and similar systems to detect any further attempts to exploit CAP_CHOWN or CAP_FOWNER capabilities.
* Review and update security policies and configurations to restrict the assignment of CAP_CHOWN and CAP_FOWNER capabilities to only trusted and necessary processes.


## Setup [_setup_1370]

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

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration:  — "-w /etc/ -p rwxa -k audit_recursive_etc"  — "-w /root/ -p rwxa -k audit_root"


## Rule query [_rule_query_5530]

```js
sequence by host.id, process.pid with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name != null and process.thread.capabilities.effective : ("CAP_CHOWN", "CAP_FOWNER") and
   process.command_line : ("*sudoers*", "*passwd*", "*shadow*", "*/root/*") and user.id != "0"]
  [file where host.os.type == "linux" and event.action == "changed-file-ownership-of" and event.type == "change" and
   event.outcome == "success" and file.path in (
     "/etc/passwd",
     "/etc/shadow",
     "/etc/sudoers",
     "/root/.ssh/*"
   ) and user.id != "0"
  ]
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



