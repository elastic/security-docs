---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/shell-execution-via-apple-scripting.html
---

# Shell Execution via Apple Scripting [shell-execution-via-apple-scripting]

Identifies the execution of the shell process (sh) via scripting (JXA or AppleScript). Adversaries may use the doShellScript functionality in JXA or do shell script in AppleScript to execute system commands.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/library/archive/technotes/tn2065/_index.html](https://developer.apple.com/library/archive/technotes/tn2065/_index.md)
* [https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_929]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Shell Execution via Apple Scripting**

AppleScript and JXA are scripting languages used in macOS to automate tasks and control applications. Adversaries exploit these by executing shell commands through functions like `doShellScript`, enabling unauthorized actions such as data exfiltration or system modification. The detection rule identifies suspicious shell processes initiated by AppleScript, focusing on specific command patterns and rapid sequence execution, indicating potential misuse.

**Possible investigation steps**

* Review the alert details to identify the specific host.id and process.entity_id involved in the suspicious activity.
* Examine the process arguments for osascript to determine the exact AppleScript command executed, focusing on the presence of the "-e" flag which indicates script execution.
* Investigate the parent process of the shell (sh, bash, zsh) to understand the context in which the shell command was executed, using process.parent.entity_id for correlation.
* Analyze the shell command arguments, particularly looking for potentially malicious patterns such as "**curl**", "**pbcopy**", "**http**", or "**chmod**", which may indicate data exfiltration or system modification attempts.
* Check the sequence and timing of the processes to assess if the execution pattern aligns with typical user behavior or if it suggests automated or rapid execution indicative of a script.
* Correlate the findings with any other security alerts or logs from the same host to identify if this activity is part of a broader attack or isolated incident.
* If necessary, escalate the investigation by capturing additional forensic data from the affected host, such as network traffic or file system changes, to further understand the impact and scope of the activity.

**False positive analysis**

* Routine administrative scripts may trigger the rule if they use AppleScript or JXA to automate tasks involving shell commands. To manage this, identify and whitelist these scripts by their specific command patterns or execution context.
* Software updates or legitimate application installations might execute shell commands through AppleScript, appearing suspicious. Monitor and document these activities, and create exceptions for known update processes.
* Development tools and environments that rely on scripting for building or testing applications can generate false positives. Exclude these processes by verifying their source and ensuring they align with expected development activities.
* User-initiated automation tasks, such as custom scripts for personal productivity, may be flagged. Educate users on safe scripting practices and establish a process for reviewing and approving such scripts to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious shell processes identified by the detection rule, specifically those initiated by `osascript` executing shell commands.
* Conduct a thorough review of the affected system’s logs and process history to identify any additional unauthorized activities or persistence mechanisms.
* Remove any unauthorized scripts or files that were executed or created as part of the malicious activity.
* Reset credentials and review permissions for any accounts that may have been compromised or used in the attack.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar patterns of behavior, focusing on the use of `osascript` and shell command execution, to prevent recurrence.


## Setup [_setup_585]

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


## Rule query [_rule_query_989]

```js
sequence by host.id with maxspan=5s
 [process where host.os.type == "macos" and event.type in ("start", "process_started", "info") and process.name == "osascript" and process.args : "-e"] by process.entity_id
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : ("sh", "bash", "zsh") and process.args == "-c" and process.args : ("*curl*", "*pbcopy*", "*http*", "*chmod*")] by process.parent.entity_id
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



