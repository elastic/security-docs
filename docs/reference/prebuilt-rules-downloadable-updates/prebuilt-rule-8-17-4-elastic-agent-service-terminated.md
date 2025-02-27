---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-elastic-agent-service-terminated.html
---

# Elastic Agent Service Terminated [prebuilt-rule-8-17-4-elastic-agent-service-terminated]

Identifies the Elastic endpoint agent has stopped and is no longer running on the host. Adversaries may attempt to disable security monitoring tools in an attempt to evade detection or prevention capabilities during an intrusion. This may also indicate an issue with the agent itself and should be addressed to ensure defensive measures are back in a stable state.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: Windows
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3959]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Elastic Agent Service Terminated**

The Elastic Agent is a crucial component for monitoring and securing endpoints across various operating systems. It ensures continuous security oversight by collecting and analyzing data. Adversaries may attempt to disable this agent to evade detection, compromising system defenses. The detection rule identifies suspicious termination activities by monitoring specific processes and commands across Windows, Linux, and macOS, flagging potential defense evasion attempts.

**Possible investigation steps**

* Review the event logs to identify the exact process and command used to terminate the Elastic Agent, focusing on the process names and arguments such as "net.exe", "sc.exe", "systemctl", and "pkill" with arguments like "stop", "uninstall", or "disable".
* Check the timeline of events around the termination to identify any preceding suspicious activities or anomalies that might indicate an adversary’s presence or actions.
* Investigate the user account associated with the process termination to determine if it was authorized or if there are signs of account compromise.
* Examine the host for any other signs of tampering or compromise, such as unauthorized changes to system configurations or the presence of other malicious processes.
* Verify the current status of the Elastic Agent on the affected host and attempt to restart it if it is not running, ensuring that security monitoring is restored.
* Correlate this event with other alerts or logs from the same host or network to identify potential patterns or coordinated attack activities.

**False positive analysis**

* Routine maintenance activities may trigger the rule if administrators use commands like systemctl or service to stop the Elastic Agent for updates or configuration changes. To manage this, create exceptions for known maintenance windows or authorized personnel.
* Automated scripts or deployment tools that temporarily disable the Elastic Agent during software installations or updates can cause false positives. Identify these scripts and whitelist their execution paths or specific arguments.
* Testing environments where Elastic Agent is frequently started and stopped for development purposes might generate alerts. Exclude these environments by specifying their hostnames or IP addresses in the rule exceptions.
* Security tools or processes that interact with the Elastic Agent, such as backup solutions or system monitoring tools, might inadvertently stop the service. Review these interactions and adjust the rule to ignore specific process names or arguments associated with these tools.
* User-initiated actions, such as troubleshooting or system performance optimization, may involve stopping the Elastic Agent. Educate users on the impact of these actions and establish a protocol for notifying the security team when such actions are necessary.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or potential lateral movement by adversaries.
* Verify the status of the Elastic Agent on the affected host and attempt to restart the service. If the service fails to restart, investigate potential causes such as corrupted files or missing dependencies.
* Conduct a thorough review of recent process execution logs on the affected host to identify any unauthorized or suspicious activities that may have led to the termination of the Elastic Agent.
* If malicious activity is confirmed, perform a comprehensive malware scan and remove any identified threats. Ensure that the host is clean before reconnecting it to the network.
* Review and update endpoint security configurations to prevent unauthorized termination of security services. This may include implementing stricter access controls or using application whitelisting.
* Escalate the incident to the security operations team for further analysis and to determine if additional hosts are affected or if there is a broader security incident underway.
* Document the incident, including all actions taken and findings, to enhance future response efforts and update incident response plans as necessary.


## Setup [_setup_912]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_4976]

```js
process where
/* net, sc or wmic stopping or deleting Elastic Agent on Windows */
(event.type == "start" and
  process.name : ("net.exe", "sc.exe", "wmic.exe","powershell.exe","taskkill.exe","PsKill.exe","ProcessHacker.exe") and
  process.args : ("stopservice","uninstall", "stop", "disabled","Stop-Process","terminate","suspend") and
  process.args : ("elasticendpoint", "Elastic Agent","elastic-agent","elastic-endpoint"))
or
/* service or systemctl used to stop Elastic Agent on Linux */
(event.type == "end" and
  (process.name : ("systemctl", "service") and
    process.args : "elastic-agent" and
    process.args : ("stop", "disable"))
  or
  /* pkill , killall used to stop Elastic Agent on Linux */
  ( event.type == "end" and process.name : ("pkill", "killall") and process.args: "elastic-agent")
  or
  /* Unload Elastic Agent extension on MacOS */
  (process.name : "kextunload" and
    process.args : "com.apple.iokit.EndpointSecurity" and
    event.action : "end"))
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



