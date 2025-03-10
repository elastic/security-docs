---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-disabling-of-apparmor.html
---

# Potential Disabling of AppArmor [prebuilt-rule-8-17-4-potential-disabling-of-apparmor]

This rule monitors for potential attempts to disable AppArmor. AppArmor is a Linux security module that enforces fine-grained access control policies to restrict the actions and resources that specific applications and processes can access. Adversaries may disable security tools to avoid possible detection of their tools and activities.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4337]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Disabling of AppArmor**

AppArmor is a Linux security module that enforces strict access controls, limiting what applications can do. Adversaries may attempt to disable AppArmor to evade detection and freely execute malicious activities. The detection rule identifies suspicious processes attempting to stop or disable AppArmor services, such as using commands like `systemctl` or `service` with specific arguments, indicating potential tampering with security defenses.

**Possible investigation steps**

* Review the process details to confirm the command used, focusing on the process name and arguments, such as "systemctl", "service", "chkconfig", or "ln" with arguments related to AppArmor.
* Check the user account associated with the process execution to determine if it is a legitimate user or potentially compromised.
* Investigate the host’s recent activity logs to identify any other suspicious behavior or anomalies around the time the alert was triggered.
* Examine the system’s AppArmor status to verify if it has been disabled or tampered with, and assess any potential impact on system security.
* Correlate this event with other alerts or logs from the same host or user to identify patterns or a broader attack campaign.
* Consult threat intelligence sources to determine if there are known adversaries or malware that commonly attempt to disable AppArmor in similar ways.

**False positive analysis**

* Routine system maintenance activities may trigger this rule, such as administrators stopping AppArmor for legitimate updates or configuration changes. To manage this, create exceptions for known maintenance windows or specific administrator accounts.
* Automated scripts or configuration management tools like Ansible or Puppet might stop or disable AppArmor as part of their deployment processes. Identify these scripts and whitelist their execution paths or associated user accounts.
* Testing environments where security modules are frequently enabled and disabled for testing purposes can generate false positives. Consider excluding these environments from the rule or adjusting the rule’s sensitivity for these specific hosts.
* Some legitimate software installations may require temporarily disabling AppArmor. Monitor installation logs and correlate them with the rule triggers to identify and exclude these benign activities.
* In environments where AppArmor is not actively used or managed, the rule may trigger on default system actions. Evaluate the necessity of monitoring AppArmor in such environments and adjust the rule scope accordingly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those attempting to disable AppArmor, to halt any ongoing malicious activities.
* Conduct a thorough review of system logs and process execution history to identify any additional indicators of compromise or related malicious activities.
* Restore AppArmor to its intended operational state by re-enabling the service and ensuring all security policies are correctly applied.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems may be affected.
* Implement enhanced monitoring on the affected system and similar environments to detect any future attempts to disable AppArmor or other security controls.
* Review and update access controls and permissions to ensure that only authorized personnel can modify security settings, reducing the risk of similar incidents.


## Setup [_setup_1185]

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


## Rule query [_rule_query_5329]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 (
  (process.name == "systemctl" and process.args in ("stop", "disable", "kill") and process.args in ("apparmor", "apparmor.service")) or
  (process.name == "service" and process.args == "apparmor" and process.args == "stop") or
  (process.name == "chkconfig" and process.args == "apparmor" and process.args == "off") or
  (process.name == "ln" and process.args : "/etc/apparmor.d/*" and process.args == "/etc/apparmor.d/disable/")
)
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



