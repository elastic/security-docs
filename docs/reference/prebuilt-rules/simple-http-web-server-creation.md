---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/simple-http-web-server-creation.html
---

# Simple HTTP Web Server Creation [simple-http-web-server-creation]

This rule detects the creation of a simple HTTP web server using PHP or Python built-in modules. Adversaries may create simple HTTP web servers to establish persistence on a compromised system by uploading a reverse or command shell payload to the server web root, allowing them to regain remote access to the system if lost.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Command and Control
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_932]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Simple HTTP Web Server Creation**

Simple HTTP web servers, often created using PHP or Python, are lightweight and easy to deploy, making them ideal for quick file sharing or testing. However, adversaries exploit this simplicity to establish persistence on compromised Linux systems. By deploying a web server, they can upload malicious payloads, such as reverse shells, to maintain remote access. The detection rule identifies suspicious server creation by monitoring process executions that match specific patterns, such as PHP or Python commands indicative of server setup, thereby alerting analysts to potential threats.

**Possible investigation steps**

* Review the process execution details to confirm the presence of PHP or Python commands with arguments matching the patterns specified in the query, such as PHP with the "-S" argument or Python with "--cgi" or "CGIHTTPServer".
* Identify the user account under which the suspicious process was executed to determine if it aligns with expected behavior or if it indicates potential compromise.
* Examine the network activity associated with the process to identify any unusual connections or data transfers that could suggest malicious intent or data exfiltration.
* Check the file system for any newly created or modified files in the web server’s root directory that could contain malicious payloads, such as reverse shells.
* Investigate the parent process of the suspicious server creation to understand how the process was initiated and whether it was triggered by another potentially malicious activity.
* Correlate the alert with other security events or logs from the same host to identify any additional indicators of compromise or related suspicious activities.

**False positive analysis**

* Development and testing environments often use simple HTTP servers for legitimate purposes such as serving static files or testing web applications. To manage this, create exceptions for known development directories or user accounts frequently involved in these activities.
* Automated scripts or cron jobs may start simple HTTP servers for routine tasks like file distribution or internal data sharing. Identify these scripts and exclude their execution paths or associated user accounts from triggering alerts.
* Educational or training sessions might involve setting up simple HTTP servers as part of learning exercises. Exclude specific IP ranges or user groups associated with training environments to prevent false positives.
* System administrators might use simple HTTP servers for quick troubleshooting or system maintenance tasks. Document these activities and create exceptions based on the administrator’s user accounts or specific server names.
* Continuous integration and deployment pipelines may temporarily start HTTP servers during build or deployment processes. Identify these pipelines and exclude their associated processes or execution contexts from the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious PHP or Python processes identified by the detection rule to halt the operation of the unauthorized web server.
* Conduct a thorough examination of the web server’s root directory to identify and remove any malicious payloads, such as reverse shells or unauthorized scripts.
* Review system logs and network traffic to identify any additional indicators of compromise or lateral movement attempts by the adversary.
* Restore the system from a known good backup if any critical system files or configurations have been altered by the adversary.
* Implement stricter access controls and monitoring on the affected system to prevent similar unauthorized server setups in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Setup [_setup_587]

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


## Rule query [_rule_query_993]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name regex~ """php?[0-9]?\.?[0-9]{0,2}""" and process.args == "-S") or
    (process.name like "python*" and process.args in ("--cgi", "CGIHTTPServer"))
  ) and
not process.parent.name in ("check_kmp_wrapper", "naemon")
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



