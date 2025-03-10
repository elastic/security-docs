---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-python-cap-setuid.html
---

# Potential Privilege Escalation via Python cap_setuid [potential-privilege-escalation-via-python-cap-setuid]

This detection rule monitors for the execution of a system command with setuid or setgid capabilities via Python, followed by a uid or gid change to the root user. This sequence of events may indicate successful privilege escalation. Setuid (Set User ID) and setgid (Set Group ID) are Unix-like OS features that enable processes to run with elevated privileges, based on the file owner or group. Threat actors can exploit these attributes to escalate privileges to the privileges that are set on the binary that is being executed.

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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_740]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Python cap_setuid**

In Unix-like systems, setuid and setgid allow processes to execute with elevated privileges, often exploited by adversaries to gain unauthorized root access. Attackers may use Python scripts to invoke system commands with these capabilities, followed by changing user or group IDs to root. The detection rule identifies this sequence by monitoring Python processes executing system commands with setuid/setgid, followed by a root user or group ID change, signaling potential privilege escalation attempts.

**Possible investigation steps**

* Review the process details, including process.entity_id and process.args, to confirm the execution of a Python script with setuid or setgid capabilities.
* Check the user.id and group.id fields to verify if there was an unauthorized change to root (user.id == "0" or group.id == "0").
* Investigate the host.id to determine if other suspicious activities or alerts have been associated with the same host.
* Examine the timeline of events to see if the uid_change or gid_change occurred immediately after the Python process execution, indicating a potential privilege escalation attempt.
* Look into the source of the Python script or command executed to identify if it was a known or unknown script, and assess its legitimacy.
* Analyze any related network activity or connections from the host around the time of the alert to identify potential lateral movement or data exfiltration attempts.

**False positive analysis**

* Development and testing environments may trigger this rule when developers use Python scripts to test setuid or setgid functionalities. To manage this, exclude specific user accounts or host IDs associated with development activities.
* Automated scripts or maintenance tasks that require temporary privilege escalation might be flagged. Identify and whitelist these scripts by their process names or paths to prevent false positives.
* System administrators using Python scripts for legitimate administrative tasks could inadvertently trigger the rule. Consider excluding known administrator accounts or specific scripts used for routine maintenance.
* Security tools or monitoring solutions that simulate attacks for testing purposes may cause alerts. Exclude these tools by their process signatures or host IDs to avoid unnecessary alerts.
* Custom applications that use Python for legitimate privilege management should be reviewed and, if safe, added to an exception list based on their unique process identifiers or execution paths.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious Python processes identified by the detection rule to halt potential privilege escalation activities.
* Review and revoke any unauthorized setuid or setgid permissions on binaries or scripts to prevent exploitation.
* Conduct a thorough investigation of the affected system to identify any additional signs of compromise or persistence mechanisms.
* Reset credentials and review access permissions for any accounts that may have been affected or used in the attack.
* Apply security patches and updates to the operating system and installed software to mitigate known vulnerabilities.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.


## Setup [_setup_475]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_787]

```js
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.args : "import os;os.set?id(0);os.system(*)" and process.args : "*python*" and user.id != "0"]
  [process where host.os.type == "linux" and event.action in ("uid_change", "gid_change") and event.type == "change" and
   (user.id == "0" or group.id == "0")]
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

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Setuid and Setgid
    * ID: T1548.001
    * Reference URL: [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)



