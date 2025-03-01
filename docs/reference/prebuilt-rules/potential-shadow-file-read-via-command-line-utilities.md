---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-shadow-file-read-via-command-line-utilities.html
---

# Potential Shadow File Read via Command Line Utilities [potential-shadow-file-read-via-command-line-utilities]

Identifies access to the /etc/shadow file via the commandline using standard system utilities. After elevating privileges to root, threat actors may attempt to read or dump this file in order to gain valid credentials. They may utilize these to move laterally undetected and access additional resources.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/](https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_772]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Shadow File Read via Command Line Utilities**

In Linux environments, the `/etc/shadow` file stores hashed passwords, making it a prime target for attackers seeking credential access. Adversaries with elevated privileges may exploit command-line utilities to read this file, aiming to extract credentials for lateral movement. The detection rule identifies suspicious access attempts by monitoring process activities related to the file, excluding legitimate operations, thus highlighting potential unauthorized access attempts.

**Possible investigation steps**

* Review the process details to identify the executable and arguments used, focusing on the process.args field to confirm access attempts to /etc/shadow.
* Check the process.parent.name field to determine the parent process and assess if it is associated with known legitimate activities or suspicious behavior.
* Investigate the user context under which the process was executed to verify if the user had legitimate reasons to access the /etc/shadow file.
* Examine the host’s recent activity logs for any privilege escalation events that might have preceded the access attempt, indicating potential unauthorized privilege elevation.
* Correlate the event with other alerts or logs from the same host to identify patterns or sequences of actions that suggest lateral movement or further credential access attempts.
* Assess the environment for any recent changes or deployments that might explain the access attempt, such as updates or configuration changes involving user management.

**False positive analysis**

* System maintenance tasks may trigger alerts when legitimate processes like chown or chmod access the /etc/shadow file. To handle these, consider excluding these specific processes when they are executed by trusted system administrators during scheduled maintenance.
* Containerized environments might generate false positives if processes within containers access the /etc/shadow file. Exclude paths such as /var/lib/docker/* or /run/containerd/* to reduce noise from container operations.
* Security tools like wazuh-modulesd or custom scripts (e.g., gen_passwd_sets) that legitimately interact with the /etc/shadow file for monitoring or compliance checks can be excluded by adding them to the process.parent.name exclusion list.
* Automated scripts or cron jobs that perform routine checks or updates on system files, including /etc/shadow, should be reviewed and, if deemed safe, excluded from triggering alerts by specifying their process names or paths in the exclusion criteria.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified in the alert that are attempting to access the /etc/shadow file.
* Conduct a thorough review of user accounts and privileges on the affected system to identify any unauthorized privilege escalations or account creations.
* Change all passwords for accounts on the affected system, especially those with elevated privileges, to mitigate the risk of credential compromise.
* Review and update access controls and permissions for sensitive files like /etc/shadow to ensure they are restricted to only necessary users and processes.
* Monitor for any further attempts to access the /etc/shadow file across the network, using enhanced logging and alerting mechanisms to detect similar threats.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_497]

**Setup**

This rule requires data coming in from Elastic Defend.

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
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_820]

```js
host.os.type : "linux" and event.category : "process" and event.action : ("exec" or "exec_event") and
(process.args : "/etc/shadow" or (process.working_directory: "/etc" and process.args: "shadow")) and not (
  (process.executable : ("/bin/chown" or "/usr/bin/chown") and process.args : "root:shadow") or
  (process.executable : ("/bin/chmod" or "/usr/bin/chmod") and process.args : "640") or
  process.executable:(/vz/* or /var/lib/docker/* or /run/containerd/* or /tmp/.criu* or /tmp/newroot/*) or
  process.parent.name:(gen_passwd_sets or scc_* or wazuh-modulesd)
)
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: /etc/passwd and /etc/shadow
    * ID: T1003.008
    * Reference URL: [https://attack.mitre.org/techniques/T1003/008/](https://attack.mitre.org/techniques/T1003/008/)



