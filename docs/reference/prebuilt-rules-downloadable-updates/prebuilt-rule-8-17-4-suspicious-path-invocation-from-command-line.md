---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-path-invocation-from-command-line.html
---

# Suspicious Path Invocation from Command Line [prebuilt-rule-8-17-4-suspicious-path-invocation-from-command-line]

This rule detects the execution of a PATH variable in a command line invocation by a shell process. This behavior is unusual and may indicate an attempt to execute a command from a non-standard location. This technique may be used to evade detection or perform unauthorized actions on the system.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/](https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4425]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Path Invocation from Command Line**

In Linux environments, shell processes like bash or zsh execute commands, often using the PATH variable to locate executables. Adversaries may manipulate PATH to run malicious scripts from non-standard directories, evading detection. The detection rule identifies unusual PATH assignments in command lines, signaling potential unauthorized actions by monitoring specific shell invocations and command patterns.

**Possible investigation steps**

* Review the command line details captured in the alert to identify the specific PATH assignment and the command being executed. This can provide insight into whether the command is expected or potentially malicious.
* Check the process tree to understand the parent process and any child processes spawned by the suspicious shell invocation. This can help determine the context in which the command was executed.
* Investigate the user account associated with the process to determine if the activity aligns with the user’s typical behavior or if the account may have been compromised.
* Examine the directory from which the command is being executed to verify if it is a non-standard or suspicious location. Look for any unusual files or scripts in that directory.
* Cross-reference the event with other security logs or alerts to identify any correlated activities that might indicate a broader attack or compromise.
* Assess the system’s recent changes or updates to determine if they could have inadvertently caused the PATH modification or if it was intentionally altered by an adversary.

**False positive analysis**

* System administrators or developers may intentionally modify the PATH variable for legitimate purposes, such as testing scripts or applications in development environments. To handle this, create exceptions for known users or specific directories commonly used for development.
* Automated scripts or configuration management tools might alter the PATH variable as part of their normal operation. Identify these scripts and exclude their execution paths or user accounts from triggering alerts.
* Some software installations or updates may temporarily change the PATH variable to include non-standard directories. Monitor installation processes and whitelist these activities when performed by trusted sources.
* Custom shell configurations or user profiles might include PATH modifications for convenience or performance reasons. Review and document these configurations, and exclude them from detection if they are verified as non-threatening.
* Educational or training environments where users experiment with shell commands may frequently trigger this rule. Consider excluding specific user groups or environments dedicated to learning and experimentation.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or data exfiltration.
* Terminate any suspicious processes identified by the alert to stop any ongoing unauthorized actions.
* Review the command history and PATH variable changes on the affected system to identify any unauthorized modifications or scripts executed from non-standard directories.
* Restore the PATH variable to its default state to ensure that only trusted directories are used for command execution.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any malicious scripts or files.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement monitoring for similar PATH manipulation attempts across the network to enhance detection and prevent recurrence.


## Setup [_setup_1268]

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


## Rule query [_rule_query_5417]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and
process.name:(bash or csh or dash or fish or ksh or sh or tcsh or zsh) and process.args:-c and
process.command_line:(*PATH=* and not sh*/run/motd.dynamic.new)
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

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)



