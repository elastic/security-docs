---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-started-from-process-id-pid-file.html
---

# Process Started from Process ID (PID) File [prebuilt-rule-8-17-4-process-started-from-process-id-pid-file]

Identifies a new process starting from a process ID (PID), lock or reboot file within the temporary file storage paradigm (tmpfs) directory /var/run directory. On Linux, the PID files typically hold the process ID to track previous copies running and manage other tasks. Certain Linux malware use the /var/run directory for holding data, executables and other tasks, disguising itself or these files as legitimate PID files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/](https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://exatrack.com/public/Tricephalic_Hellkeeper.pdf](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf)
* [https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor](https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Threat: BPFDoor
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4403]

**Triage and analysis**

**Investigating Process Started from Process ID (PID) File**

Detection alerts from this rule indicate a process spawned from an executable masqueraded as a legitimate PID file which is very unusual and should not occur. Here are some possible avenues of investigation: - Examine parent and child process relationships of the new process to determine if other processes are running. - Examine the /var/run directory using Osquery to determine other potential PID files with unsually large file sizes, indicative of it being an executable: "SELECT f.size, f.uid, f.type, f.path from file f WHERE path like */var/run/%%*;" - Examine the reputation of the SHA256 hash from the PID file in a database like VirusTotal to identify additional pivots and artifacts for investigation.


## Setup [_setup_1247]

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


## Rule query [_rule_query_5395]

```js
process where host.os.type == "linux" and event.type == "start" and user.id == "0" and
  process.executable regex~ """/var/run/\w+\.(pid|lock|reboot)"""
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



