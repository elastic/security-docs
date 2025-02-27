---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-hidden-files-and-directories-via-commandline.html
---

# Creation of Hidden Files and Directories via CommandLine [creation-of-hidden-files-and-directories-via-commandline]

Users can mark specific files as hidden simply by putting a "." as the first character in the file or folder name. Adversaries can use this to their advantage to hide files and folders on the system for persistence and defense evasion. This rule looks for hidden files or folders in common writable directories.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 112

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_237]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Creation of Hidden Files and Directories via CommandLine**

In Linux environments, files and directories prefixed with a dot (.) are hidden by default, a feature often exploited by adversaries to conceal malicious activities. Attackers may create hidden files in writable directories like /tmp to evade detection. The detection rule identifies suspicious processes creating such hidden files, excluding benign commands, to flag potential threats. This helps in uncovering stealthy persistence and defense evasion tactics.

**Possible investigation steps**

* Review the process details to identify the command executed, focusing on the process.working_directory field to confirm if the hidden file was created in a common writable directory like /tmp, /var/tmp, or /dev/shm.
* Examine the process.args field to determine the specific hidden file or directory name created, and assess if it matches known malicious patterns or naming conventions.
* Check the process lineage by investigating the parent process to understand the context of how the hidden file creation was initiated and identify any potential malicious parent processes.
* Investigate the user account associated with the process to determine if it is a legitimate user or potentially compromised, and review recent activities by this user for any anomalies.
* Search for any additional hidden files or directories created around the same time or by the same process to identify further suspicious activities or artifacts.
* Correlate this event with other security alerts or logs from the same host to identify any related suspicious activities or patterns that could indicate a broader attack or compromise.

**False positive analysis**

* System maintenance scripts may create hidden files in directories like /tmp for temporary storage. Review these scripts and consider excluding them if they are verified as non-threatening.
* Development tools and processes, such as version control systems or build scripts, might generate hidden files for configuration or state tracking. Identify these tools and add them to the exclusion list if they are part of regular operations.
* Monitoring and logging tools may use hidden files to store temporary data or logs. Verify these tools and exclude them if they are essential for system monitoring.
* User-specific applications or scripts might create hidden files for legitimate purposes. Conduct a review of user activities and exclude known benign applications to reduce noise.
* Automated backup or synchronization services could generate hidden files as part of their operation. Confirm these services and exclude them if they are part of the expected environment setup.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious processes identified by the detection rule that are creating hidden files in the specified directories.
* Remove any hidden files or directories created by unauthorized processes in the /tmp, /var/tmp, and /dev/shm directories to eliminate potential persistence mechanisms.
* Conduct a thorough review of system logs and process execution history to identify any additional indicators of compromise or related malicious activities.
* Restore any affected files or system components from a known good backup to ensure system integrity.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar activities to improve detection and response capabilities for future incidents.


## Setup [_setup_156]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://docs/reference/auditbeat/setting-up-running.md).

**Custom Ingest Pipeline**

For versions <8.2, you need to add a custom ingest pipeline to populate `event.ingested` with @timestamp for non-elastic-agent indexes, like auditbeats/filebeat/winlogbeat etc. For more details to add a custom ingest pipeline refer to the [guide](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md).


## Rule query [_rule_query_246]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.working_directory in ("/tmp", "/var/tmp", "/dev/shm") and
process.args regex~ """\.[a-z0-9_\-][a-z0-9_\-\.]{1,254}""" and
not process.name in (
  "ls", "find", "grep", "git", "jq", "basename", "check_snmp", "snmpget", "snmpwalk", "cc1plus", "snap",
  "command-not-found", "sqlite", "apk", "fgrep", "locate", "objdump"
)
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



