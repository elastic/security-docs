---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-disable-syslog-service.html
---

# Attempt to Disable Syslog Service [attempt-to-disable-syslog-service]

Adversaries may attempt to disable the syslog service in an attempt to an attempt to disrupt event logging and evade detection by security controls.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security](https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_154]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Disable Syslog Service**

Syslog is a critical component in Linux environments, responsible for logging system events and activities. Adversaries may target syslog to disable logging, thereby evading detection and obscuring their malicious actions. The detection rule identifies attempts to stop or disable syslog services by monitoring specific process actions and arguments, flagging suspicious commands that could indicate an attempt to impair logging defenses.

**Possible investigation steps**

* Review the process details to identify the user account associated with the command execution, focusing on the process.name and process.args fields to determine if the action was legitimate or suspicious.
* Check the system’s recent login history and user activity to identify any unauthorized access attempts or anomalies around the time the syslog service was targeted.
* Investigate the parent process of the flagged command to understand the context of its execution and determine if it was initiated by a legitimate application or script.
* Examine other logs and alerts from the same host around the time of the event to identify any correlated suspicious activities or patterns that might indicate a broader attack.
* Assess the system for any signs of compromise, such as unexpected changes in configuration files, unauthorized software installations, or unusual network connections, to determine if the attempt to disable syslog is part of a larger attack.

**False positive analysis**

* Routine maintenance activities may trigger this rule, such as scheduled service restarts or system updates. To manage this, create exceptions for known maintenance windows or specific administrative accounts performing these tasks.
* Automated scripts or configuration management tools like Ansible or Puppet might stop or disable syslog services as part of their operations. Identify these scripts and whitelist their execution paths or associated user accounts.
* Testing environments often simulate service disruptions, including syslog, for resilience testing. Exclude these environments from the rule or adjust the rule to ignore specific test-related processes.
* Some legitimate software installations or updates may require stopping syslog services temporarily. Monitor installation logs and exclude these processes if they are verified as non-threatening.
* In environments with multiple syslog implementations, ensure that the rule is not overly broad by refining the process arguments to match only the specific syslog services in use.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and potential lateral movement by the adversary.
* Terminate any suspicious processes identified in the alert, specifically those attempting to stop or disable syslog services, to restore normal logging functionality.
* Restart the syslog service on the affected system to ensure that logging is re-enabled and operational, using commands like `systemctl start syslog` or `service syslog start`.
* Conduct a thorough review of recent logs, if available, to identify any additional suspicious activities or indicators of compromise that may have occurred prior to the syslog service being disabled.
* Escalate the incident to the security operations team for further investigation and to determine if the attack is part of a larger campaign or if other systems are affected.
* Implement additional monitoring on the affected system and similar systems to detect any further attempts to disable logging services, using enhanced logging and alerting mechanisms.
* Review and update access controls and permissions to ensure that only authorized personnel have the ability to modify or stop critical services like syslog, reducing the risk of future incidents.


## Setup [_setup_94]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_158]

```js
process where host.os.type == "linux" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
 ( (process.name == "service" and process.args == "stop") or
   (process.name == "chkconfig" and process.args == "off") or
   (process.name == "systemctl" and process.args in ("disable", "stop", "kill"))
 ) and process.args in ("syslog", "rsyslog", "syslog-ng", "syslog.service", "rsyslog.service", "syslog-ng.service") and
not process.parent.name == "rsyslog-rotate"
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



