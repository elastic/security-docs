---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-shell-via-wildcard-injection-detected.html
---

# Potential Shell via Wildcard Injection Detected [prebuilt-rule-8-17-4-potential-shell-via-wildcard-injection-detected]

This rule monitors for the execution of a set of linux binaries, that are potentially vulnerable to wildcard injection, with suspicious command line flags followed by a shell spawn event. Linux wildcard injection is a type of security vulnerability where attackers manipulate commands or input containing wildcards (e.g., *, ?, []) to execute unintended operations or access sensitive data by tricking the system into interpreting the wildcard characters in unexpected ways.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4531]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Shell via Wildcard Injection Detected**

Wildcard injection exploits vulnerabilities in Linux command-line utilities by manipulating wildcard characters to execute unauthorized commands. Adversaries leverage this to escalate privileges or execute arbitrary code. The detection rule identifies suspicious use of vulnerable binaries like `tar`, `rsync`, and `zip` followed by shell execution, indicating potential exploitation attempts.

**Possible investigation steps**

* Review the process details to identify the specific command executed, focusing on the process name and arguments, especially those involving `tar`, `rsync`, or `zip` with suspicious flags like `--checkpoint=*`, `-e*`, or `--unzip-command`.
* Examine the parent process information to determine if a shell process (e.g., `bash`, `sh`, `zsh`) was spawned, indicating potential exploitation.
* Check the process execution path to ensure it does not match the exclusion pattern `/tmp/newroot/*`, which might indicate a benign operation.
* Investigate the host’s recent activity logs to identify any other suspicious or related events that might indicate a broader attack or compromise.
* Correlate the alert with any other security events or alerts from the same host to assess if this is part of a larger attack pattern or campaign.
* Assess the user account associated with the process execution to determine if it has the necessary privileges and if the activity aligns with expected behavior for that account.

**False positive analysis**

* Legitimate use of tar, rsync, or zip with wildcard-related flags in automated scripts or backup processes can trigger false positives. Review the context of these processes and consider excluding specific scripts or directories from monitoring if they are verified as safe.
* System administrators or maintenance scripts may use shell commands following tar, rsync, or zip for legitimate purposes. Identify these routine operations and create exceptions for known safe parent processes or specific command patterns.
* Development environments or testing scenarios might involve intentional use of wildcard characters for testing purposes. Exclude these environments from the rule or adjust the rule to ignore specific user accounts or process paths associated with development activities.
* Scheduled tasks or cron jobs that involve the use of these binaries with wildcard flags can be mistaken for malicious activity. Verify the legitimacy of these tasks and exclude them based on their schedule or specific command line arguments.
* Security tools or monitoring solutions that simulate attacks for testing or validation purposes might trigger this rule. Ensure these tools are recognized and excluded from monitoring to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified in the alert, particularly those involving the execution of shell commands following the use of `tar`, `rsync`, or `zip`.
* Conduct a thorough review of the affected system’s logs to identify any additional indicators of compromise or unauthorized access attempts.
* Restore the affected system from a known good backup if any unauthorized changes or malicious activities are confirmed.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Implement file integrity monitoring on critical systems to detect unauthorized changes to system binaries or configuration files.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1363]

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


## Rule query [_rule_query_5523]

```js
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and (
    (process.name == "tar" and process.args : "--checkpoint=*" and process.args : "--checkpoint-action=*") or
    (process.name == "rsync" and process.args : "-e*") or
    (process.name == "zip" and process.args == "--unzip-command")
   ) and not process.executable : "/tmp/newroot/*"
  ]  by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
     process.parent.name : ("tar", "rsync", "zip") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
  ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



