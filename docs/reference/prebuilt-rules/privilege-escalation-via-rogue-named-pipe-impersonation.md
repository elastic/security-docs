---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/privilege-escalation-via-rogue-named-pipe-impersonation.html
---

# Privilege Escalation via Rogue Named Pipe Impersonation [privilege-escalation-via-rogue-named-pipe-impersonation]

Identifies a privilege escalation attempt via rogue named pipe impersonation. An adversary may abuse this technique by masquerading as a known named pipe and manipulating a privileged process to connect to it.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
* [https://twitter.com/SBousseaden/status/1429530155291193354](https://twitter.com/SBousseaden/status/1429530155291193354)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_820]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via Rogue Named Pipe Impersonation**

Named pipes in Windows facilitate inter-process communication, allowing data exchange between processes. Adversaries exploit this by creating rogue named pipes, tricking privileged processes into connecting and executing malicious actions under elevated privileges. The detection rule identifies suspicious named pipe creation events, focusing on patterns indicative of impersonation attempts, thus flagging potential privilege escalation activities.

**Possible investigation steps**

* Review the event logs for the specific named pipe creation event identified by the query, focusing on the file.name field to determine the exact named pipe path and assess its legitimacy.
* Correlate the event with the process that created the named pipe by examining related process creation logs, identifying the process ID and executable responsible for the action.
* Investigate the user context under which the named pipe was created to determine if it aligns with expected behavior or if it indicates potential misuse of privileges.
* Check for any recent changes or anomalies in the system’s configuration or user accounts that could suggest unauthorized access or privilege escalation attempts.
* Analyze historical data for similar named pipe creation events to identify patterns or repeated attempts that could indicate a persistent threat or ongoing attack.

**False positive analysis**

* Legitimate software or system processes may create named pipes that match the detection pattern. Regularly review and whitelist known benign processes that frequently create named pipes to reduce noise.
* System management tools and monitoring software might generate named pipe creation events as part of their normal operation. Identify these tools and exclude their events from triggering alerts.
* Custom in-house applications that use named pipes for inter-process communication can trigger false positives. Work with development teams to document these applications and create exceptions for their activity.
* Scheduled tasks or scripts that run with elevated privileges and create named pipes could be mistaken for malicious activity. Ensure these tasks are documented and excluded from the detection rule.
* Security software or endpoint protection solutions may use named pipes for legitimate purposes. Verify these activities and adjust the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes associated with the rogue named pipe to halt any ongoing malicious activities.
* Conduct a thorough review of the system’s event logs, focusing on named pipe creation events, to identify any other potentially compromised processes or systems.
* Reset credentials for any accounts that may have been exposed or used in the privilege escalation attempt to prevent further unauthorized access.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Implement enhanced monitoring for named pipe creation events across the network to detect and respond to similar threats in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation efforts are undertaken.


## Setup [_setup_538]

**Setup**

Named Pipe Creation Events need to be enabled within the Sysmon configuration by including the following settings: `condition equal "contains" and keyword equal "pipe"`

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_874]

```js
file where host.os.type == "windows" and event.action : "Pipe Created*" and
 /* normal sysmon named pipe creation events truncate the pipe keyword */
  file.name : "\\*\\Pipe\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



