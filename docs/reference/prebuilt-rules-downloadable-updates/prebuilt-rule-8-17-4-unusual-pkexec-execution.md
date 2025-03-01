---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-pkexec-execution.html
---

# Unusual Pkexec Execution [prebuilt-rule-8-17-4-unusual-pkexec-execution]

This rule detects the execution of the `pkexec` command by a shell process. The `pkexec` command is used to execute programs as another user, typically as the superuser. Through the `new_terms` rule type, unusual executions of `pkexec` are identified, and may indicate an attempt to escalate privileges or perform unauthorized actions on the system.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Execution
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4426]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Pkexec Execution**

`Pkexec` is a command-line utility in Linux environments that allows users to execute commands as another user, often with elevated privileges. Adversaries may exploit `pkexec` to escalate privileges or execute unauthorized actions by invoking it through shell processes. The detection rule identifies atypical `pkexec` executions initiated by common shell interpreters, flagging potential misuse by monitoring specific process attributes and execution patterns.

**Possible investigation steps**

* Review the process tree to understand the context of the pkexec execution, focusing on the parent process names such as bash, dash, sh, tcsh, csh, zsh, ksh, or fish, as these are indicative of shell-based invocations.
* Examine the command-line arguments passed to pkexec to determine the intended action and assess whether it aligns with expected administrative tasks or appears suspicious.
* Check the user account associated with the pkexec execution to verify if the account has legitimate reasons to perform such actions, and investigate any anomalies in user behavior or account activity.
* Investigate the timing and frequency of the pkexec executions to identify patterns or correlations with other suspicious activities or known attack timelines.
* Cross-reference the alert with other security logs and alerts from data sources like Elastic Endgame, Elastic Defend, Crowdstrike, or SentinelOne to gather additional context and corroborate findings.
* Assess the system’s current state for signs of compromise, such as unauthorized changes, unexpected network connections, or the presence of known malicious files or processes.

**False positive analysis**

* Routine administrative tasks: System administrators may use pkexec for legitimate purposes, such as performing maintenance tasks. To handle this, create exceptions for known administrator accounts or specific maintenance scripts that regularly invoke pkexec.
* Automated scripts: Some automated scripts or cron jobs might use pkexec to perform scheduled tasks. Identify these scripts and exclude their specific process names or paths from the rule to prevent false alerts.
* Software updates: Certain software update processes might use pkexec to apply patches or updates. Monitor and document these processes, then configure exceptions for recognized update mechanisms.
* Development environments: Developers might use pkexec during testing or development. Establish a list of development machines or user accounts and exclude them from the rule to reduce noise.
* Custom user applications: Users may have custom applications that require pkexec for legitimate functionality. Review these applications and whitelist their specific execution patterns to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious `pkexec` processes identified by the alert to halt unauthorized actions or privilege escalation attempts.
* Review and analyze the parent shell process and its command history to understand the context and origin of the `pkexec` execution.
* Reset credentials and review permissions for the user accounts involved to mitigate any unauthorized access or privilege escalation.
* Conduct a thorough scan of the affected system for additional indicators of compromise or persistence mechanisms that may have been deployed.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Update and enhance monitoring rules to detect similar `pkexec` misuse attempts in the future, ensuring comprehensive coverage of shell processes and privilege escalation activities.


## Setup [_setup_1269]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend

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


## Rule query [_rule_query_5418]

```js
event.category:process and host.os.type:linux and event.type:start and
event.action:(exec or exec_event or start or ProcessRollup2) and process.name:pkexec and
process.args:pkexec and process.parent.name:(bash or dash or sh or tcsh or csh or zsh or ksh or fish)
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

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



