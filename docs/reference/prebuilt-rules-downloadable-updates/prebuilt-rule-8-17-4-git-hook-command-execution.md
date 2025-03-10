---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-git-hook-command-execution.html
---

# Git Hook Command Execution [prebuilt-rule-8-17-4-git-hook-command-execution]

This rule detects the execution of a potentially malicious process from a Git hook. Git hooks are scripts that Git executes before or after events such as: commit, push, and receive. An attacker can abuse Git hooks to execute arbitrary commands on the system and establish persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4452]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Git Hook Command Execution**

Git hooks are scripts that automate tasks by executing before or after Git events like commits or pushes. While useful for developers, adversaries can exploit them to run malicious commands, gaining persistence or evading defenses. The detection rule identifies suspicious processes initiated by Git hooks, focusing on shell executions, to flag potential abuse on Linux systems.

**Possible investigation steps**

* Review the alert details to identify the specific Git hook script path and the suspicious process name that was executed, as indicated by the process.args and process.name fields.
* Examine the process tree to understand the parent-child relationship, focusing on the process.parent.name and process.entity_id fields, to determine how the suspicious process was initiated.
* Check the Git repository’s history and recent changes to the .git/hooks directory to identify any unauthorized modifications or additions to the hook scripts.
* Investigate the user account associated with the process execution to determine if the activity aligns with their typical behavior or if it indicates potential compromise.
* Analyze the command-line arguments and environment variables of the suspicious process to gather more context on the nature of the executed command.
* Correlate this event with other security alerts or logs from the same host.id to identify any patterns or additional indicators of compromise.
* If possible, isolate the affected system and conduct a deeper forensic analysis to uncover any further malicious activity or persistence mechanisms.

**False positive analysis**

* Developers using Git hooks for legitimate automation tasks may trigger this rule. To manage this, identify and document common scripts used in your development environment and create exceptions for these known benign processes.
* Continuous integration and deployment (CI/CD) systems often utilize Git hooks to automate workflows. Review the processes initiated by these systems and exclude them from detection if they are verified as non-malicious.
* Custom scripts executed via Git hooks for project-specific tasks can also cause false positives. Collaborate with development teams to catalog these scripts and adjust the detection rule to exclude them.
* Frequent updates or changes in Git repositories might lead to repeated triggering of the rule. Monitor these activities and, if consistent and verified as safe, consider adding them to an allowlist to reduce noise.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified as being executed from Git hooks, especially those involving shell executions.
* Conduct a thorough review of the .git/hooks directory on the affected system to identify and remove any unauthorized or malicious scripts.
* Restore any modified or deleted files from a known good backup to ensure system integrity.
* Implement monitoring for any future modifications to the .git/hooks directory to detect unauthorized changes promptly.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Review and update access controls and permissions for Git repositories to limit the ability to modify hooks to trusted users only.


## Setup [_setup_1295]

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


## Rule query [_rule_query_5444]

```js
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.parent.name == "git" and process.args : ".git/hooks/*" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

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



