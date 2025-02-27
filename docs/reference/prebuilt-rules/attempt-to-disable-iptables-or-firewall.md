---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-disable-iptables-or-firewall.html
---

# Attempt to Disable IPTables or Firewall [attempt-to-disable-iptables-or-firewall]

Adversaries may attempt to disable the iptables or firewall service in an attempt to affect how a host is allowed to receive or send network traffic.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

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
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 110

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_153]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Disable IPTables or Firewall**

Firewalls like IPTables on Linux systems are crucial for controlling network traffic and protecting against unauthorized access. Adversaries may attempt to disable these firewalls to bypass security measures and facilitate malicious activities. The detection rule identifies suspicious processes that attempt to disable or stop firewall services, such as using commands to flush IPTables rules or halt firewall services, indicating potential defense evasion tactics.

**Possible investigation steps**

* Review the process details, including process.name and process.args, to confirm if the command was intended to disable or stop firewall services.
* Check the process.parent.args to understand the context in which the suspicious process was executed, especially if it was triggered by a parent process with arguments like "force-stop".
* Investigate the user account associated with the process execution to determine if it was an authorized user or potentially compromised.
* Examine the host’s recent activity logs for any other suspicious behavior or anomalies around the time of the alert, focusing on event.type "start" and event.action "exec" or "exec_event".
* Assess the network traffic logs to identify any unusual inbound or outbound connections that might have occurred after the firewall was disabled or stopped.
* Correlate this event with other alerts or incidents involving the same host or user to identify potential patterns or coordinated attack attempts.

**False positive analysis**

* Routine system maintenance or updates may trigger the rule when legitimate processes like systemctl or service are used to stop or restart firewall services. To manage this, create exceptions for known maintenance scripts or scheduled tasks that perform these actions.
* Network troubleshooting activities often involve temporarily disabling firewalls to diagnose connectivity issues. Users can exclude specific user accounts or IP addresses associated with network administrators from triggering the rule during these activities.
* Automated deployment scripts that configure or reconfigure firewall settings might match the rule’s criteria. Identify and whitelist these scripts by their process names or execution paths to prevent false positives.
* Security software updates or installations may require temporary firewall adjustments, which could be flagged by the rule. Consider excluding processes associated with trusted security software vendors during update windows.
* Development or testing environments often have different security requirements, leading to frequent firewall changes. Implement environment-specific exceptions to avoid false positives in these contexts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Terminate any suspicious processes identified in the alert, such as those attempting to disable or stop firewall services, to halt ongoing malicious activities.
* Review and restore the firewall configurations to their last known good state to ensure that network traffic is properly controlled and unauthorized access is blocked.
* Conduct a thorough examination of the affected system for any signs of compromise or additional malicious activity, focusing on logs and system changes around the time of the alert.
* Escalate the incident to the security operations team for further analysis and to determine if the threat is part of a larger attack campaign.
* Implement additional monitoring and alerting for similar activities across the network to detect and respond to future attempts to disable firewall services promptly.
* Review and update firewall policies and configurations to enhance security measures and prevent similar defense evasion tactics in the future.


## Setup [_setup_93]

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


## Rule query [_rule_query_157]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
  (
   /* disable FW */
   (
     (process.name == "ufw" and process.args == "disable") or
     (process.name == "iptables" and process.args in ("-F", "--flush", "-X", "--delete-chain") and process.args_count == 2) or
     (process.name in ("iptables", "ip6tables") and process.parent.args == "force-stop")
   ) or

   /* stop FW service */
   (
     ((process.name == "service" and process.args == "stop") or
       (process.name == "chkconfig" and process.args == "off") or
       (process.name == "systemctl" and process.args in ("disable", "stop", "kill"))) and
    process.args in ("firewalld", "ip6tables", "iptables", "firewalld.service", "ip6tables.service", "iptables.service")
    )
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



