---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-symbolic-link-created.html
---

# Suspicious Symbolic Link Created [prebuilt-rule-8-17-4-suspicious-symbolic-link-created]

Identifies the creation of a symbolic link to a suspicious file or location. A symbolic link is a reference to a file or directory that acts as a pointer or shortcut, allowing users to access the target file or directory from a different location in the file system. An attacker can potentially leverage symbolic links for privilege escalation by tricking a privileged process into following the symbolic link to a sensitive file, giving the attacker access to data or capabilities they would not normally have.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Privilege Escalation
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4522]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Symbolic Link Created**

Symbolic links in Linux are shortcuts that point to files or directories, facilitating easy access. Adversaries may exploit these links to redirect privileged processes to sensitive files, potentially escalating privileges or accessing restricted data. The detection rule identifies suspicious link creation by monitoring the execution of the *ln* command with specific arguments and targets, especially when initiated by non-root users, indicating potential misuse.

**Possible investigation steps**

* Review the process details to confirm the execution of the *ln* command with suspicious arguments such as "-s" or "-sf" and verify the target files or directories listed in the query, like "/etc/shadow" or "/bin/bash".
* Check the user and group IDs associated with the process to ensure they are not root (ID "0"), as the rule specifically targets non-root users.
* Investigate the parent process name to determine if it is one of the shell processes listed in the query, such as "bash" or "zsh", which might indicate a user-initiated action.
* Examine the working directory and arguments to identify if the symbolic link creation is targeting sensitive locations like "/etc/cron.d/**" or "/home/**/.ssh/*".
* Analyze the user’s recent activity and command history to understand the context and intent behind the symbolic link creation.
* Correlate this event with other security alerts or logs to identify any patterns or additional suspicious activities involving the same user or system.

**False positive analysis**

* Non-root users creating symbolic links for legitimate administrative tasks may trigger the rule. To manage this, identify and whitelist specific users or groups who regularly perform these tasks without malicious intent.
* Automated scripts or applications that use symbolic links for configuration management or software deployment might be flagged. Review these processes and exclude them by specifying the script or application names in the detection rule.
* Development environments where symbolic links are used to manage dependencies or version control can cause false positives. Exclude directories or processes associated with these environments to prevent unnecessary alerts.
* Backup or synchronization tools that create symbolic links as part of their operation may be mistakenly identified. Identify these tools and add exceptions for their typical execution patterns.
* System maintenance activities that involve symbolic link creation, such as linking to shared libraries or binaries, should be reviewed and excluded if they are part of routine operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the attacker.
* Terminate any suspicious processes related to the *ln* command that are identified in the alert to stop any ongoing malicious activity.
* Conduct a thorough review of the symbolic links created, especially those pointing to sensitive files or directories, and remove any unauthorized or suspicious links.
* Reset credentials and review access permissions for any accounts that may have been compromised or used in the attack, focusing on those with elevated privileges.
* Restore any altered or compromised files from a known good backup to ensure system integrity and prevent further exploitation.
* Implement additional monitoring and logging for symbolic link creation and other related activities to detect similar threats in the future.
* Escalate the incident to the security operations team for further investigation and to assess the need for broader organizational response measures.


## Setup [_setup_1354]

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


## Rule query [_rule_query_5514]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "ln" and process.args in ("-s", "-sf") and
  (
    /* suspicious files */
    (process.args in ("/etc/shadow", "/etc/shadow-", "/etc/shadow~", "/etc/gshadow", "/etc/gshadow-") or
    (process.working_directory == "/etc" and process.args in ("shadow", "shadow-", "shadow~", "gshadow", "gshadow-"))) or

    /* suspicious bins */
    (process.args in ("/bin/bash", "/bin/dash", "/bin/sh", "/bin/tcsh", "/bin/csh", "/bin/zsh", "/bin/ksh", "/bin/fish") or
    (process.working_directory == "/bin" and process.args : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"))) or
    (process.args in ("/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh", "/usr/bin/tcsh", "/usr/bin/csh", "/usr/bin/zsh", "/usr/bin/ksh", "/usr/bin/fish") or
    (process.working_directory == "/usr/bin" and process.args in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"))) or

    /* suspicious locations */
    (process.args : ("/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*")) or
    (process.args : ("/home/*/.ssh/*", "/root/.ssh/*","/etc/sudoers.d/*", "/dev/shm/*"))
  ) and
  process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  not user.Ext.real.id == "0" and not group.Ext.real.id == "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: /etc/passwd and /etc/shadow
    * ID: T1003.008
    * Reference URL: [https://attack.mitre.org/techniques/T1003/008/](https://attack.mitre.org/techniques/T1003/008/)



