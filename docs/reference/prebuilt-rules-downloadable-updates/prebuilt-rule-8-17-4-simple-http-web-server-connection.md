---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-simple-http-web-server-connection.html
---

# Simple HTTP Web Server Connection [prebuilt-rule-8-17-4-simple-http-web-server-connection]

This rule detects connections accepted by a simple HTTP web server in Python and PHP built-in modules. Adversaries may create simple HTTP web servers to establish persistence on a compromised system by uploading a reverse or command shell payload to the server web root, allowing them to regain remote access to the system if lost. This event may occur when an attacker requests the server to execute a command or script via a potential backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.network*

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
* Tactic: Persistence
* Tactic: Execution
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4490]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Simple HTTP Web Server Connection**

Simple HTTP servers in Python and PHP are often used for development and testing, providing a quick way to serve web content. However, attackers can exploit these servers to maintain access on compromised Linux systems by deploying backdoors or executing commands remotely. The detection rule identifies suspicious server activity by monitoring for specific process patterns and command-line arguments indicative of these lightweight servers, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the process details, including the process name and command line arguments, to confirm if the server was started using Python or PHP, as indicated by the query fields.
* Check the network connection details associated with the event, such as the source and destination IP addresses and ports, to identify any suspicious or unexpected connections.
* Investigate the user account under which the process was initiated to determine if it aligns with expected behavior or if it indicates potential unauthorized access.
* Examine the system logs and any related events around the time of the alert to identify any additional suspicious activities or anomalies.
* Assess the server’s web root directory for any unauthorized files or scripts that could indicate a backdoor or malicious payload.
* Correlate this event with other alerts or indicators of compromise on the system to evaluate if this is part of a larger attack campaign.

**False positive analysis**

* Development and testing environments may frequently trigger this rule when developers use Python or PHP’s built-in HTTP servers for legitimate purposes. To manage this, consider excluding specific user accounts or IP addresses associated with development activities from the rule.
* Automated scripts or cron jobs that start simple HTTP servers for routine tasks can also generate false positives. Identify these scripts and add their process names or command-line patterns to an exception list.
* Educational or training environments where students are learning web development might cause alerts. In such cases, exclude the network segments or user groups associated with these activities.
* Internal tools or services that rely on lightweight HTTP servers for functionality might be flagged. Review these tools and whitelist their specific process names or command-line arguments to prevent unnecessary alerts.
* Temporary testing servers spun up for short-term projects can be mistaken for malicious activity. Document these instances and apply temporary exceptions during the project duration.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious Python or PHP processes identified by the detection rule to stop the potential backdoor or unauthorized server activity.
* Conduct a thorough review of the system’s file system, focusing on the web root directory, to identify and remove any unauthorized scripts or payloads that may have been uploaded.
* Change all credentials associated with the compromised system, including SSH keys and passwords, to prevent attackers from regaining access.
* Restore the system from a known good backup if any unauthorized changes or persistent threats are detected that cannot be easily remediated.
* Implement network monitoring to detect any future unauthorized HTTP server activity, focusing on unusual process patterns and command-line arguments.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1328]

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


## Rule query [_rule_query_5482]

```js
network where host.os.type == "linux" and event.type == "start" and event.action == "connection_accepted" and (
  (process.name regex~ """php?[0-9]?\.?[0-9]{0,2}""" and process.command_line like "*-S*") or
  (process.name like "python*" and process.command_line like ("*--cgi*", "*CGIHTTPServer*"))
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Web Shell
    * ID: T1505.003
    * Reference URL: [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)

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

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



