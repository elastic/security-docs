---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/webserver-access-logs-deleted.html
---

# WebServer Access Logs Deleted [webserver-access-logs-deleted]

Identifies the deletion of WebServer access logs. This may indicate an attempt to evade detection or destroy forensic evidence on a system.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.sysmon_operational-*

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
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1195]

**Triage and analysis**

[TBC: QUOTE]
**Investigating WebServer Access Logs Deleted**

Web server access logs are crucial for monitoring and analyzing web traffic, providing insights into user activity and potential security incidents. Adversaries may delete these logs to cover their tracks, hindering forensic investigations. The detection rule identifies log deletions across various operating systems by monitoring specific file paths, signaling potential attempts at evasion or evidence destruction.

**Possible investigation steps**

* Review the specific file path where the deletion event was detected to determine which web server’s logs were affected, using the file.path field from the alert.
* Check for any recent access or modification events on the affected web server to identify potential unauthorized access or suspicious activity prior to the log deletion.
* Investigate user accounts and processes that had access to the deleted log files around the time of the deletion event to identify potential malicious actors or compromised accounts.
* Correlate the log deletion event with other security alerts or anomalies in the same timeframe to identify patterns or related incidents.
* Examine backup logs or alternative logging mechanisms, if available, to recover deleted information and assess the impact of the log deletion on forensic capabilities.

**False positive analysis**

* Routine log rotation or maintenance scripts may delete old web server logs. To handle this, identify and exclude these scheduled tasks from triggering alerts by specifying their execution times or associated process names.
* Automated backup processes that move or delete logs after archiving can trigger false positives. Exclude these processes by adding exceptions for the backup software or scripts used.
* Development or testing environments where logs are frequently cleared to reset the environment can cause alerts. Consider excluding these environments by specifying their IP addresses or hostnames.
* System administrators manually deleting logs as part of regular maintenance can be mistaken for malicious activity. Implement a policy to log and approve such actions, and exclude these approved activities from detection.
* Temporary log deletions during server migrations or upgrades might trigger alerts. Document these events and create temporary exceptions during the migration period.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of recent user activity and system changes to identify any unauthorized access or modifications that may have led to the log deletion.
* Restore the deleted web server access logs from backups, if available, to aid in further forensic analysis and investigation.
* Implement enhanced monitoring on the affected system to detect any further attempts at log deletion or other suspicious activities.
* Review and tighten access controls and permissions on log files to ensure only authorized personnel can modify or delete them.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Document the incident, including all actions taken, and update incident response plans to improve future detection and response capabilities.


## Setup [_setup_755]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1221]

```js
file where event.type == "deletion" and
  file.path : ("C:\\inetpub\\logs\\LogFiles\\*.log",
               "/var/log/apache*/access.log",
               "/etc/httpd/logs/access_log",
               "/var/log/httpd/access_log",
               "/var/www/*/logs/access.log")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)



