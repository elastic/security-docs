---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-git-hook-child-process.html
---

# Git Hook Child Process [prebuilt-rule-8-17-4-git-hook-child-process]

This rule detects child processes spawned by Git hooks. Git hooks are scripts that Git executes before or after events such as commit, push, and receive. The rule identifies child processes spawned by Git hooks that are not typically spawned by the Git process itself. This behavior may indicate an attacker attempting to hide malicious activity by leveraging the legitimate Git process to execute unauthorized commands.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://git-scm.com/docs/githooks/2.26.0](https://git-scm.com/docs/githooks/2.26.0)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4455]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Git Hook Child Process**

Git hooks are scripts that automate tasks during Git operations like commits or pushes. Adversaries may exploit these hooks to execute unauthorized commands, masking malicious activities under legitimate processes. The detection rule identifies unusual child processes spawned by Git hooks, focusing on atypical scripts or executables in suspicious directories, signaling potential misuse.

**Possible investigation steps**

* Review the process tree to understand the parent-child relationship, focusing on the parent process names listed in the query, such as "pre-commit" or "post-update", to determine the context of the spawned child process.
* Examine the command line arguments and environment variables of the suspicious child process to identify any potentially malicious or unauthorized commands being executed.
* Check the file paths of the executables involved, especially those in unusual directories like "/tmp/**" or "/var/tmp/**", to assess if they are legitimate or potentially harmful.
* Investigate the user account under which the suspicious process is running to determine if it has been compromised or is being used in an unauthorized manner.
* Correlate the event with other security logs or alerts from the same host to identify any patterns or additional indicators of compromise.
* Review recent Git activity on the repository to identify any unauthorized changes or suspicious commits that might indicate tampering with Git hooks.

**False positive analysis**

* Legitimate development scripts: Developers may use scripts in directories like /tmp or /var/tmp for testing purposes. To handle this, create exceptions for known scripts or directories used by trusted developers.
* Custom shell usage: Developers might use shells like bash or zsh for legitimate automation tasks. Identify and whitelist these specific shell scripts if they are part of regular development workflows.
* Temporary file execution: Some applications may temporarily execute files from directories like /dev/shm or /run. Monitor these applications and exclude them if they are verified as non-threatening.
* Non-standard interpreters: Developers might use interpreters like php or perl for legitimate tasks. Review and whitelist these processes if they are part of approved development activities.
* System maintenance scripts: Scheduled tasks or maintenance scripts might run from /etc/cron.* or /etc/init.d. Verify these scripts and exclude them if they are part of routine system operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or execution of malicious commands.
* Terminate any suspicious processes identified by the detection rule, especially those originating from unusual directories or involving unexpected scripts or executables.
* Conduct a thorough review of the Git hooks on the affected system to identify and remove any unauthorized or malicious scripts.
* Restore any modified or deleted files from a known good backup to ensure system integrity and continuity of operations.
* Implement stricter access controls and permissions for Git repositories and associated directories to prevent unauthorized modifications to Git hooks.
* Monitor the affected system and related network activity closely for any signs of persistence or further compromise, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been affected.


## Setup [_setup_1298]

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


## Rule query [_rule_query_5447]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.parent.name in (
    "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update", "post-checkout", "post-commit",
    "pre-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "pre-push", "pre-rebase", "pre-receive",
    "push-to-checkout", "update", "post-receive", "pre-auto-gc", "post-rewrite", "sendemail-validate", "p4-pre-submit",
    "post-index-change", "post-merge", "post-applypatch"
  ) and
  (
    process.name in ("nohup", "setsid", "disown", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
    process.name : ("php*", "perl*", "ruby*", "lua*") or
    process.executable : (
      "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*",
      "/run/*", "/srv/*", "/tmp/*", "/var/tmp/*", "/var/log/*"
    )
  ) and
  not process.name in ("git", "dirname")
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



