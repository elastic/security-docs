---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-binary-executed-from-shared-memory-directory.html
---

# Binary Executed from Shared Memory Directory [prebuilt-rule-8-17-4-binary-executed-from-shared-memory-directory]

Identifies the execution of a binary by root in Linux shared memory directories: (/dev/shm/, /run/shm/, /var/run/, /var/lock/). This activity is to be considered highly abnormal and should be investigated. Threat actors have placed executables used for persistence on high-uptime servers in these directories as system backdoors.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://linuxsecurity.com/features/fileless-malware-on-linux](https://linuxsecurity.com/features/fileless-malware-on-linux)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor](https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Threat: BPFDoor
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4404]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Binary Executed from Shared Memory Directory**

Shared memory directories in Linux, such as /dev/shm and /run/shm, are designed for efficient inter-process communication. However, adversaries exploit these directories to execute binaries stealthily, often as root, bypassing traditional security measures. The detection rule identifies such anomalies by monitoring for root-executed binaries in these directories, excluding known legitimate processes, thus flagging potential backdoor activities.

**Possible investigation steps**

* Review the process executable path to confirm it resides in a shared memory directory such as /dev/shm, /run/shm, /var/run, or /var/lock, and verify it is not part of the known exclusions like /var/run/docker or /var/run/utsns.
* Investigate the parent process of the suspicious executable to understand the context of its execution, focusing on the command line used, especially if it does not match the exclusion pattern /usr/bin/runc init.
* Check the process’s creation time and correlate it with any other suspicious activities or alerts around the same timeframe to identify potential patterns or related incidents.
* Analyze the binary file in question for any known malicious signatures or unusual characteristics using tools like file integrity checkers or antivirus solutions.
* Review system logs and audit logs for any unauthorized access or privilege escalation attempts that might have led to the execution of the binary as root.
* Investigate the user account activity associated with user.id "0" to ensure there are no signs of compromise or misuse of root privileges.
* If possible, isolate the affected system to prevent further potential malicious activity while the investigation is ongoing.

**False positive analysis**

* Docker-related processes can trigger false positives when binaries are executed from shared memory directories. To mitigate this, exclude paths like /var/run/docker/* from the detection rule.
* Processes related to container orchestration tools such as Kubernetes might also cause false positives. Exclude paths like /var/run/utsns/* and /var/run/s6/* to prevent these.
* Cloudera services may execute binaries from shared memory directories as part of their normal operations. Exclude /var/run/cloudera-scm-agent/* to avoid false alerts.
* Argo workflows might execute binaries in these directories. Exclude /var/run/argo/argoexec to reduce false positives.
* Legitimate use of /usr/bin/runc init as a parent process can be excluded to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the threat actor.
* Terminate any suspicious processes running from the shared memory directories (/dev/shm, /run/shm, /var/run, /var/lock) to halt potential malicious activity.
* Conduct a thorough review of the system’s process tree and logs to identify any additional malicious binaries or scripts that may have been executed or are scheduled to run.
* Remove any unauthorized binaries or scripts found in the shared memory directories and other critical system paths to eliminate persistence mechanisms.
* Restore the system from a known good backup if the integrity of the system is compromised and cannot be assured through manual remediation.
* Implement enhanced monitoring and alerting for any future execution of binaries from shared memory directories, ensuring that legitimate processes are whitelisted appropriately.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1248]

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


## Rule query [_rule_query_5396]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
user.id == "0" and process.executable : ("/dev/shm/*", "/run/shm/*", "/var/run/*", "/var/lock/*") and
not process.executable : ("/var/run/docker/*", "/var/run/utsns/*", "/var/run/s6/*", "/var/run/cloudera-scm-agent/*",
"/var/run/argo/argoexec") and not process.parent.command_line : "/usr/bin/runc init"
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



