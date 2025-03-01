---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-emond-child-process.html
---

# Suspicious Emond Child Process [suspicious-emond-child-process]

Identifies the execution of a suspicious child process of the Event Monitor Daemon (emond). Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.xorrior.com/emond-persistence/](https://www.xorrior.com/emond-persistence/)
* [https://www.elastic.co/security-labs/handy-elastic-tools-for-the-enthusiastic-detection-engineer](https://www.elastic.co/security-labs/handy-elastic-tools-for-the-enthusiastic-detection-engineer)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_980]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Emond Child Process**

The Event Monitor Daemon (emond) on macOS is a service that executes commands based on system events, like startup or user login. Adversaries exploit emond by crafting rules that trigger malicious scripts or commands during these events, enabling persistence. The detection rule identifies unusual child processes spawned by emond, such as shell scripts or command-line utilities, which are indicative of potential abuse.

**Possible investigation steps**

* Review the process details to confirm the parent process is indeed emond and check the specific child process name against the list of suspicious processes such as bash, python, or curl.
* Investigate the command line arguments used by the suspicious child process to identify any potentially malicious commands or scripts being executed.
* Check the timing of the event to see if it coincides with known system events like startup or user login, which could indicate an attempt to establish persistence.
* Examine the user account associated with the process to determine if it is a legitimate user or potentially compromised account.
* Look for any recent changes to emond rules or configuration files that could have been modified to trigger the suspicious process execution.
* Correlate this event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise.

**False positive analysis**

* System maintenance scripts may trigger the rule if they use shell scripts or command-line utilities. Review scheduled tasks or maintenance scripts and exclude them if they are verified as non-threatening.
* Legitimate software installations or updates might spawn processes like bash or curl. Monitor installation logs and exclude these processes if they align with known software updates.
* User-initiated scripts for automation or customization can cause alerts. Verify the user’s intent and exclude these processes if they are part of regular user activity.
* Administrative tasks performed by IT staff, such as using launchctl for service management, may trigger the rule. Confirm these activities with IT staff and exclude them if they are part of routine administration.
* Development environments on macOS might use interpreters like Python or Perl. Validate the development activities and exclude these processes if they are consistent with the developer’s workflow.

**Response and remediation**

* Isolate the affected macOS system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious child processes spawned by emond, such as shell scripts or command-line utilities, to halt ongoing malicious actions.
* Review and remove any unauthorized or suspicious emond rules that may have been added to execute malicious commands during system events.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or persistence mechanisms.
* Restore any altered or deleted system files from a known good backup to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for emond and related processes to detect similar threats in the future, ensuring alerts are configured for unusual child processes.


## Setup [_setup_623]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_1028]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.parent.name : "emond" and
 process.name : (
   "bash",
   "dash",
   "sh",
   "tcsh",
   "csh",
   "zsh",
   "ksh",
   "fish",
   "Python",
   "python*",
   "perl*",
   "php*",
   "osascript",
   "pwsh",
   "curl",
   "wget",
   "cp",
   "mv",
   "touch",
   "echo",
   "base64",
   "launchctl")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Emond
    * ID: T1546.014
    * Reference URL: [https://attack.mitre.org/techniques/T1546/014/](https://attack.mitre.org/techniques/T1546/014/)



