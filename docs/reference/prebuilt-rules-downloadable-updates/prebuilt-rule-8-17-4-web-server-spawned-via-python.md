---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-web-server-spawned-via-python.html
---

# Web Server Spawned via Python [prebuilt-rule-8-17-4-web-server-spawned-via-python]

This rule identifies when a web server is spawned via Python. Attackers may use Python to spawn a web server to exfiltrate/infiltrate data or to move laterally within a network.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4406]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Web Server Spawned via Python**

Python’s built-in HTTP server module allows quick web server deployment, often used for testing or file sharing. Adversaries exploit this to exfiltrate data or facilitate lateral movement within networks. The detection rule identifies processes starting a Python-based server, focusing on command patterns and shell usage, to flag potential misuse on Linux systems.

**Possible investigation steps**

* Review the process details to confirm the presence of a Python-based web server by checking the process name and arguments, specifically looking for "python" with "http.server" or "SimpleHTTPServer".
* Investigate the user account associated with the process to determine if it is a known or expected user for running such services.
* Examine the command line used to start the process for any unusual or suspicious patterns, especially if it involves shell usage like "bash" or "sh" with the command line containing "python -m http.server".
* Check the network activity from the host to identify any unusual outbound connections or data transfers that could indicate data exfiltration.
* Correlate the event with other logs or alerts from the same host to identify any preceding or subsequent suspicious activities that might suggest lateral movement or further exploitation attempts.
* Assess the host’s security posture and recent changes to determine if there are any vulnerabilities or misconfigurations that could have been exploited to spawn the web server.

**False positive analysis**

* Development and testing environments often use Python’s HTTP server for legitimate purposes such as serving static files or testing web applications. To manage this, create exceptions for known development servers by excluding specific hostnames or IP addresses.
* Automated scripts or cron jobs may start a Python web server for routine tasks like file distribution within a controlled environment. Identify these scripts and exclude their execution paths or user accounts from the detection rule.
* Educational or training sessions might involve participants using Python’s HTTP server to learn web technologies. Exclude these activities by setting time-based exceptions during scheduled training periods.
* System administrators might use Python’s HTTP server for quick file transfers or troubleshooting. Document these use cases and exclude the associated user accounts or process command lines from triggering alerts.
* Internal tools or utilities developed in-house may rely on Python’s HTTP server for functionality. Review these tools and exclude their specific command patterns or execution contexts from the detection rule.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further data exfiltration or lateral movement.
* Terminate the suspicious Python process identified by the detection rule to stop the unauthorized web server.
* Conduct a forensic analysis of the affected system to identify any data that may have been accessed or exfiltrated and to determine the initial access vector.
* Review and secure any exposed credentials or sensitive data that may have been compromised during the incident.
* Apply patches and updates to the affected system and any related software to mitigate vulnerabilities that may have been exploited.
* Implement network segmentation to limit the ability of unauthorized processes to communicate across the network.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation and recovery actions are taken.


## Setup [_setup_1250]

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


## Rule query [_rule_query_5398]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name like "python*" and process.args in ("http.server", "SimpleHTTPServer")) or
    (
      process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
      process.command_line like~ "*python* -m http.server*"
    )
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

* Sub-technique:

    * Name: Python
    * ID: T1059.006
    * Reference URL: [https://attack.mitre.org/techniques/T1059/006/](https://attack.mitre.org/techniques/T1059/006/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Lateral Tool Transfer
    * ID: T1570
    * Reference URL: [https://attack.mitre.org/techniques/T1570/](https://attack.mitre.org/techniques/T1570/)



