---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/directory-creation-in-bin-directory.html
---

# Directory Creation in /bin directory [directory-creation-in-bin-directory]

This rule identifies the creation of directories in the /bin directory. The /bin directory contains essential binary files that are required for the system to function properly. The creation of directories in this location could be an attempt to hide malicious files or executables, as these /bin directories usually just contain binaries.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Defense Evasion
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_268]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Directory Creation in /bin directory**

The /bin directory is crucial for Linux systems, housing essential binaries for system operations. Adversaries may exploit this by creating directories here to conceal malicious files, leveraging the directory’s trusted status. The detection rule identifies suspicious directory creation by monitoring *mkdir* executions in critical binary paths, excluding legitimate system operations, thus flagging potential threats for further investigation.

**Possible investigation steps**

* Review the process details to confirm the execution of *mkdir* in the specified critical binary paths such as /bin, /usr/bin, /usr/local/bin, /sbin, /usr/sbin, and /usr/local/sbin.
* Check the parent process of the *mkdir* command to determine if it was initiated by a legitimate system process or a potentially malicious one.
* Investigate the user account associated with the *mkdir* process to assess if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Examine the system logs around the time of the directory creation for any other suspicious activities or anomalies that might indicate a broader attack.
* Verify if any files or executables have been placed in the newly created directory and assess their legitimacy and potential threat level.
* Cross-reference the event with threat intelligence sources to identify if the activity matches any known malicious patterns or indicators of compromise.

**False positive analysis**

* System updates or package installations may trigger directory creation in the /bin directory as part of legitimate operations. Users can mitigate this by creating exceptions for known package management processes like apt, yum, or rpm.
* Custom scripts or administrative tasks that require creating directories in the /bin directory for temporary storage or testing purposes can also lead to false positives. Users should document and exclude these specific scripts or tasks from the detection rule.
* Automated deployment tools or configuration management systems such as Ansible, Puppet, or Chef might create directories in the /bin directory as part of their setup routines. Users should identify these tools and add them to the exclusion list to prevent unnecessary alerts.
* Development or testing environments where developers have permissions to create directories in the /bin directory for application testing can result in false positives. Users should differentiate between production and non-production environments and apply the rule accordingly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Terminate any suspicious processes related to the directory creation in the /bin directory to halt any ongoing malicious activity.
* Conduct a thorough review of the newly created directories and files within the /bin directory to identify and remove any malicious binaries or scripts.
* Restore any altered or deleted legitimate binaries from a known good backup to ensure system integrity and functionality.
* Implement file integrity monitoring on critical system directories, including /bin, to detect unauthorized changes in real-time.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are compromised.
* Review and update access controls and permissions for the /bin directory to restrict unauthorized directory creation and enhance security posture.


## Setup [_setup_175]

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


## Rule query [_rule_query_278]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "start", "ProcessRollup2", "exec_event") and process.name == "mkdir" and
  process.args like ("/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*") and
not process.args in ("/bin/mkdir", "/usr/bin/mkdir", "/usr/local/bin/mkdir")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



