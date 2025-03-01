---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-binary-path-file-permission-modification.html
---

# System Binary Path File Permission Modification [system-binary-path-file-permission-modification]

This rule identifies file permission modification events on files located in common system binary paths. Adversaries may attempt to hide their payloads in the default Linux system directories, and modify the file permissions of these payloads prior to execution.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1058]

**Triage and analysis**

[TBC: QUOTE]
**Investigating System Binary Path File Permission Modification**

In Linux environments, system binary paths contain critical executables. Adversaries may exploit these by altering file permissions to execute malicious payloads. The detection rule monitors processes like `chmod` and `chown` in key directories, flagging suspicious permission changes. It excludes benign activities, focusing on unauthorized modifications to prevent potential execution of harmful scripts.

**Possible investigation steps**

* Review the process details to identify the exact command executed, focusing on the process name and arguments, especially those involving `chmod` or `chown` in critical directories like `/bin`, `/usr/bin`, and `/lib`.
* Examine the parent process information, including the executable path and command line, to determine if the process was initiated by a known or trusted application, excluding those like `udevadm`, `systemd`, or `sudo`.
* Check the user account associated with the process to verify if the action was performed by an authorized user or if there are signs of compromised credentials.
* Investigate the file or directory whose permissions were modified to assess its importance and potential impact, focusing on changes to permissions like `4755`, `755`, or `777`.
* Correlate the event with other security alerts or logs to identify any related suspicious activities, such as unauthorized access attempts or unexpected script executions.
* Review recent changes or updates in the system that might explain the permission modification, ensuring they align with legitimate administrative tasks or software installations.

**False positive analysis**

* System updates and package installations often involve legitimate permission changes in system binary paths. Users can exclude processes with parent executables located in directories like /var/lib/dpkg/info to reduce noise from these activities.
* Administrative scripts or automation tools may execute chmod or chown commands as part of routine maintenance. Exclude processes with parent names such as udevadm, systemd, or sudo to prevent these from being flagged.
* Container initialization processes might trigger permission changes. Exclude processes with parent command lines like runc init to avoid false positives related to container setups.
* Temporary script executions during software installations can cause permission modifications. Exclude processes with parent arguments matching patterns like /var/tmp/rpm-tmp.* to filter out these benign events.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or execution of malicious payloads.
* Terminate any suspicious processes identified as executing `chmod` or `chown` commands in critical system binary paths.
* Revert any unauthorized file permission changes to their original state to ensure system integrity and prevent execution of malicious scripts.
* Conduct a thorough review of system logs and process execution history to identify any additional unauthorized activities or related threats.
* Escalate the incident to the security operations team for further investigation and to determine if the threat has spread to other systems.
* Implement additional monitoring on the affected system and similar environments to detect any recurrence of unauthorized permission modifications.
* Review and update access controls and permissions policies to minimize the risk of unauthorized modifications in critical system directories.


## Setup [_setup_665]

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


## Rule query [_rule_query_1108]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name in ("chmod", "chown") and
process.args like~ (
  "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*",
  "/lib/*", "/usr/lib/*", "/lib64/*", "/usr/lib64/*"
) and
process.args in ("4755", "755", "000", "777", "444", "-x", "+x") and not (
  process.args in ("/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod") or
  process.parent.executable like~ ("/tmp/newroot/*", "/var/lib/dpkg/info/*") or
  process.parent.name in ("udevadm", "systemd", "entrypoint", "sudo", "dart") or
  process.parent.command_line == "runc init" or
  process.parent.args like "/var/tmp/rpm-tmp.*"
)
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



