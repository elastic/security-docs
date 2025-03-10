---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-kworker-uid-elevation.html
---

# Suspicious Kworker UID Elevation [suspicious-kworker-uid-elevation]

Monitors for the elevation of regular user permissions to root permissions through the kworker process. kworker, or kernel worker, processes are part of the kernel’s workqueue mechanism. They are responsible for executing work that has been scheduled to be done in kernel space, which might include tasks like handling interrupts, background activities, and other kernel-related tasks. Attackers may attempt to evade detection by masquerading as a kernel worker process, and hijack the execution flow by hooking certain functions/syscalls through a rootkit in order to provide easy access to root via a special modified command.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_999]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Kworker UID Elevation**

Kworker processes are integral to Linux, handling tasks like interrupts and background activities within the kernel. Adversaries may exploit these processes by disguising malicious activities as legitimate kernel operations, often using rootkits to hijack execution flow and gain root access. The detection rule identifies anomalies by monitoring for kworker processes that unexpectedly change session IDs and elevate privileges to root, signaling potential misuse.

**Possible investigation steps**

* Review the process details for the kworker process with a session ID change and user ID of 0 to confirm the legitimacy of the process and its parent process.
* Check the system logs around the time of the session ID change event for any unusual activities or errors that might indicate tampering or exploitation attempts.
* Investigate any recent changes to the system, such as new software installations or updates, that could have introduced vulnerabilities or unauthorized modifications.
* Analyze the system for signs of rootkit presence, such as hidden files or processes, by using rootkit detection tools or manual inspection techniques.
* Correlate the event with other security alerts or anomalies in the network to determine if this is part of a broader attack campaign or isolated incident.

**False positive analysis**

* Regular system updates or maintenance activities may trigger session ID changes in kworker processes. Users can monitor scheduled maintenance windows and exclude these time frames from triggering alerts.
* Custom kernel modules or legitimate software that interacts with kernel processes might cause kworker to change session IDs. Identify and whitelist these known modules or software to prevent false positives.
* Automated scripts or tools that require elevated privileges for legitimate tasks could inadvertently cause kworker processes to appear suspicious. Review and document these scripts, then create exceptions for their expected behavior.
* Certain system configurations or optimizations might lead to benign kworker session ID changes. Conduct a baseline analysis of normal system behavior and adjust the detection rule to accommodate these patterns without compromising security.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the attacker.
* Terminate the suspicious kworker process identified in the alert to stop any ongoing malicious activity.
* Conduct a thorough review of system logs and process trees to identify any additional compromised processes or indicators of rootkit installation.
* Restore the system from a known good backup if rootkit presence is confirmed, as rootkits can deeply embed themselves into the system.
* Change all credentials and keys that may have been exposed or used on the compromised system to prevent unauthorized access using stolen credentials.
* Implement enhanced monitoring and logging for kworker processes and session ID changes to detect similar activities in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems.


## Setup [_setup_631]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click Add integrations.
* In the query bar, search for Elastic Defend and select the integration to see more details about it.
* Click Add Elastic Defend.
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either Traditional Endpoints or Cloud Workloads.
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in New agent policy name. If other agent policies already exist, you can click the Existing hosts tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click Save and Continue.
* To complete the integration, select Add Elastic Agent to your hosts and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_1048]

```js
process where host.os.type == "linux" and event.action == "session_id_change" and process.name : "kworker*" and
user.id == "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: KernelCallbackTable
    * ID: T1574.013
    * Reference URL: [https://attack.mitre.org/techniques/T1574/013/](https://attack.mitre.org/techniques/T1574/013/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



