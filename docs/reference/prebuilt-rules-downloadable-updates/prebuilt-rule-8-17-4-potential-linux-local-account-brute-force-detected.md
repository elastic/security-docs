---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-linux-local-account-brute-force-detected.html
---

# Potential Linux Local Account Brute Force Detected [prebuilt-rule-8-17-4-potential-linux-local-account-brute-force-detected]

Identifies multiple consecutive login attempts executed by one process targeting a local linux user account within a short time interval. Adversaries might brute force login attempts across different users with a default wordlist or a set of customly crafted passwords in an attempt to gain access to these accounts.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4318]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Linux Local Account Brute Force Detected**

In Linux environments, the *su* command is used to switch user accounts, often requiring a password. Adversaries exploit this by attempting numerous logins with various passwords to gain unauthorized access. The detection rule identifies suspicious activity by monitoring rapid, repeated *su* command executions from a single process, excluding common legitimate parent processes, indicating potential brute force attempts.

**Possible investigation steps**

* Review the process execution details to identify the parent process of the *su* command, focusing on any unusual or unauthorized parent processes not listed in the exclusion list.
* Analyze the frequency and pattern of the *su* command executions from the identified process to determine if they align with typical user behavior or indicate a brute force attempt.
* Check the user account targeted by the *su* command attempts to assess if it is a high-value or sensitive account that might be of interest to adversaries.
* Investigate the source host (host.id) to determine if there are any other suspicious activities or anomalies associated with it, such as unusual network connections or other security alerts.
* Correlate the event timestamps with other logs or alerts to identify any concurrent suspicious activities that might indicate a coordinated attack effort.

**False positive analysis**

* Legitimate administrative scripts or automation tools may trigger the rule if they execute the *su* command frequently. To mitigate this, identify and whitelist these scripts or tools by adding their parent process names to the exclusion list.
* Scheduled tasks or cron jobs that require switching users might be misidentified as brute force attempts. Review and exclude these tasks by specifying their parent process names in the exclusion criteria.
* Development or testing environments where frequent user switching is part of normal operations can generate false positives. Consider excluding these environments from monitoring or adjust the detection threshold to better fit the operational context.
* Continuous integration or deployment systems that use the *su* command for user context switching can be mistaken for brute force attempts. Add these systems' parent process names to the exclusion list to prevent false alerts.

**Response and remediation**

* Immediately isolate the affected host to prevent further unauthorized access or lateral movement within the network.
* Terminate the suspicious process identified by the detection rule to stop ongoing brute force attempts.
* Reset passwords for the targeted user accounts to prevent unauthorized access using potentially compromised credentials.
* Review and update the password policy to enforce strong, complex passwords and consider implementing account lockout mechanisms after a certain number of failed login attempts.
* Conduct a thorough review of the affected system for any signs of successful unauthorized access or additional malicious activity, such as new user accounts or scheduled tasks.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Enhance monitoring and logging on the affected host and similar systems to detect and respond to future brute force attempts more effectively.


## Setup [_setup_1169]

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


## Rule query [_rule_query_5310]

```js
sequence by host.id, process.parent.executable, user.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "su" and
   not process.parent.name in (
     "bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "clickhouse-server", "ma", "gitlab-runner",
     "updatedb.findutils", "cron", "perl", "sudo", "java", "cloud-app-identify", "ambari-sudo.sh"
   )
  ] with runs=10
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Password Guessing
    * ID: T1110.001
    * Reference URL: [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)



