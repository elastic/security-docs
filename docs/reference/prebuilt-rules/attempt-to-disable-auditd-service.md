---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-disable-auditd-service.html
---

# Attempt to Disable Auditd Service [attempt-to-disable-auditd-service]

Adversaries may attempt to disable the Auditd service to evade detection. Auditd is a Linux service that provides system auditing and logging. Disabling the Auditd service can prevent the system from logging important security events, which can be used to detect malicious activity.

**Rule type**: eql

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_151]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Disable Auditd Service**

Auditd is a critical Linux service responsible for system auditing and logging, capturing security-relevant events. Adversaries may target this service to evade detection by disabling it, thus preventing the logging of their activities. The detection rule identifies suspicious processes attempting to stop or disable Auditd, such as using commands like `service stop` or `systemctl disable`, signaling potential defense evasion tactics.

**Possible investigation steps**

* Review the process details to identify the user account associated with the suspicious command execution, focusing on the process fields such as process.name and process.args.
* Check the system logs for any preceding or subsequent suspicious activities around the time of the alert, particularly looking for other defense evasion tactics or unauthorized access attempts.
* Investigate the command history of the user identified to determine if there are any other unauthorized or suspicious commands executed.
* Verify the current status of the Auditd service on the affected host to ensure it is running and properly configured.
* Correlate the alert with any other security events or alerts from the same host or user to identify potential patterns or broader attack campaigns.

**False positive analysis**

* System administrators may intentionally stop or disable the Auditd service during maintenance or troubleshooting. To handle this, create exceptions for known maintenance windows or specific administrator accounts.
* Automated scripts or configuration management tools might stop or disable Auditd as part of routine system updates or deployments. Identify these scripts and whitelist their activities to prevent false alerts.
* Some Linux distributions or custom setups might have alternative methods for managing services that could trigger this rule. Review and adjust the detection criteria to align with the specific service management practices of your environment.
* In environments where Auditd is not used or is replaced by another logging service, the rule might trigger unnecessarily. Consider disabling the rule or adjusting its scope in such cases.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and potential lateral movement by the adversary.
* Terminate any suspicious processes identified in the alert that are attempting to disable the Auditd service to stop the adversary’s actions.
* Re-enable and restart the Auditd service on the affected system to ensure that auditing and logging are resumed, capturing any further suspicious activities.
* Conduct a thorough review of the system logs and audit records to identify any unauthorized changes or additional indicators of compromise that may have occurred prior to the alert.
* Apply any necessary security patches or updates to the affected system to address vulnerabilities that may have been exploited by the adversary.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement enhanced monitoring and alerting for similar activities across the network to detect and respond to future attempts to disable critical security services.


## Setup [_setup_91]

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


## Rule query [_rule_query_155]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and (
  (process.name == "service" and process.args == "stop") or
  (process.name == "chkconfig" and process.args == "off") or
  (process.name == "systemctl" and process.args in ("disable", "stop", "kill"))
) and
process.args in ("auditd", "auditd.service") and
not process.parent.name == "auditd.prerm"
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



