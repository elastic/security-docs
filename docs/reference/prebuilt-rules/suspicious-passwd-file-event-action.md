---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-passwd-file-event-action.html
---

# Suspicious Passwd File Event Action [suspicious-passwd-file-event-action]

Monitors for the generation of a passwd password entry via openssl, followed by a file write activity on the "/etc/passwd" file. The "/etc/passwd" file in Linux stores user account information, including usernames, user IDs, group IDs, home directories, and default shell paths. Attackers may exploit a misconfiguration in the "/etc/passwd" file permissions or other privileges to add a new entry to the "/etc/passwd" file with root permissions, and leverage this new user account to login as root.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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

## Investigation guide [_investigation_guide_1014]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Passwd File Event Action**

In Linux environments, the `/etc/passwd` file is crucial for managing user accounts. Adversaries may exploit vulnerabilities or misconfigurations to add unauthorized entries, potentially gaining root access. The detection rule monitors for the use of `openssl` to generate password entries and subsequent unauthorized modifications to the `/etc/passwd` file, flagging potential privilege escalation attempts.

**Possible investigation steps**

* Review the process execution details to confirm the use of *openssl* with the *passwd* argument by a non-root user (user.id != "0"). This can help identify the user attempting to generate a password entry.
* Examine the process tree to understand the parent process of the *openssl* command and determine if it was initiated by a legitimate or suspicious process.
* Check the file modification event on */etc/passwd* to verify if the file was altered by a non-root user (user.id != "0") and ensure the process.parent.pid is not 1, indicating it wasn’t initiated by the init process.
* Investigate the context of the file write event by reviewing recent logs and system changes to identify any unauthorized modifications or anomalies in user account management.
* Correlate the event with other security alerts or logs to determine if there are additional indicators of compromise or related suspicious activities on the host.

**False positive analysis**

* System administrators or automated scripts may use openssl to manage user passwords without malicious intent. To handle this, identify and whitelist known administrative scripts or processes that perform legitimate password management tasks.
* Some legitimate software installations or updates might temporarily modify the /etc/passwd file. Monitor and document these activities to distinguish them from unauthorized changes, and consider creating exceptions for known software processes.
* Developers or testers might use openssl for password generation in non-production environments. Establish a policy to differentiate between production and non-production systems, and apply the rule more strictly in production environments.
* Scheduled maintenance tasks might involve legitimate modifications to the /etc/passwd file. Coordinate with IT teams to schedule these tasks and temporarily adjust monitoring rules during these periods to prevent false positives.
* In environments with multiple administrators, ensure that all legitimate administrative actions are logged and reviewed. Implement a process for administrators to report their activities, allowing for the creation of exceptions for known, non-threatening actions.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or privilege escalation attempts.
* Terminate any suspicious processes related to `openssl` or unauthorized modifications to the `/etc/passwd` file to halt ongoing malicious activities.
* Conduct a thorough review of the `/etc/passwd` file to identify and remove any unauthorized entries, especially those with root privileges.
* Reset passwords for all user accounts on the affected system to ensure no compromised credentials are used for further attacks.
* Restore the `/etc/passwd` file from a known good backup if unauthorized changes are detected and cannot be manually rectified.
* Escalate the incident to the security operations team for a comprehensive investigation into potential system vulnerabilities or misconfigurations that allowed the attack.
* Implement enhanced monitoring and alerting for similar activities, focusing on unauthorized use of `openssl` and modifications to critical system files like `/etc/passwd`.


## Setup [_setup_639]

**Setup**

This rule requires data coming in from Elastic Defend and Auditd Manager.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

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

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration:  — "-w /etc/passwd -p wa -k etcpasswd"


## Rule query [_rule_query_1065]

```js
sequence by host.id, process.parent.pid with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "openssl" and process.args == "passwd" and user.id != "0"]
  [file where host.os.type == "linux" and file.path == "/etc/passwd" and process.parent.pid != 1 and
   not auditd.data.a2 == "80000" and event.outcome == "success" and user.id != "0"]
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



