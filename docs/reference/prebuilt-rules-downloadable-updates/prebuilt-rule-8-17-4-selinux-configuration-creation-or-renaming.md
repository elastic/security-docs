---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-selinux-configuration-creation-or-renaming.html
---

# SELinux Configuration Creation or Renaming [prebuilt-rule-8-17-4-selinux-configuration-creation-or-renaming]

This rule detects the creation or renaming of the SELinux configuration file. SELinux is a security module that provides access control security policies. Modifications to the SELinux configuration file may indicate an attempt to impair defenses by disabling or modifying security tools.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* endgame-*
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
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4359]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SELinux Configuration Creation or Renaming**

SELinux, a Linux kernel security module, enforces access control policies to protect systems. Adversaries may target the SELinux configuration file to disable or alter these defenses, facilitating unauthorized access or evasion of security measures. The detection rule identifies suspicious activities like file creation or renaming in the SELinux configuration path, signaling potential defense evasion attempts.

**Possible investigation steps**

* Review the alert details to confirm the event action is either "creation", "file_create_event", "rename", or "file_rename_event" and that the file path is "/etc/selinux/config".
* Check the timestamp of the event to determine when the SELinux configuration file was created or renamed.
* Identify the user account and process responsible for the action by examining the event logs for associated user and process information.
* Investigate the history of changes to the SELinux configuration file to determine if there have been any recent unauthorized modifications.
* Correlate the event with other security alerts or logs to identify any related suspicious activities or patterns on the host.
* Assess the current state of SELinux on the affected system to ensure it is configured correctly and has not been disabled or altered inappropriately.
* If unauthorized changes are confirmed, initiate a response plan to mitigate potential security risks, which may include restoring the original configuration and conducting a broader security assessment of the system.

**False positive analysis**

* Routine system updates or administrative tasks may trigger file creation or renaming events in the SELinux configuration path. Users can create exceptions for known update processes or trusted administrative scripts to prevent unnecessary alerts.
* Automated configuration management tools like Ansible, Puppet, or Chef might modify the SELinux configuration file as part of their normal operations. Users should identify and whitelist these tools to reduce false positives.
* Initial system setup or reconfiguration activities often involve legitimate changes to the SELinux configuration. Users can temporarily disable the rule during planned maintenance windows or add exceptions for specific time frames to avoid false alerts.
* Security audits or compliance checks may involve accessing or modifying SELinux settings. Users should coordinate with audit teams to recognize these activities and adjust the rule settings accordingly.
* Custom scripts or applications developed in-house that interact with SELinux settings should be reviewed and, if deemed safe, added to an exception list to minimize false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Verify the integrity of the SELinux configuration file by comparing it with a known good backup. If discrepancies are found, restore the file from a trusted backup.
* Conduct a thorough review of recent user and process activity on the affected system to identify any unauthorized changes or suspicious behavior that may have led to the SELinux configuration modification.
* Re-enable SELinux enforcement if it has been disabled, and ensure that the correct security policies are applied to maintain system protection.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement additional monitoring on the affected system and similar systems to detect any further attempts to modify SELinux configurations or other critical security settings.
* Review and update access controls and permissions to ensure that only authorized personnel have the ability to modify SELinux configurations, reducing the risk of future unauthorized changes.


## Setup [_setup_1207]

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


## Rule query [_rule_query_5351]

```js
file where host.os.type == "linux" and event.action in ("creation", "file_create_event", "rename", "file_rename_event")
and file.path : "/etc/selinux/config" and not process.name in ("dockerd", "platform-python")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



