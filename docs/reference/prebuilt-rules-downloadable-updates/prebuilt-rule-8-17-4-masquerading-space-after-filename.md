---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-masquerading-space-after-filename.html
---

# Masquerading Space After Filename [prebuilt-rule-8-17-4-masquerading-space-after-filename]

This rules identifies a process created from an executable with a space appended to the end of the filename. This may indicate an attempt to masquerade a malicious file as benign to gain user execution. When a space is added to the end of certain files, the OS will execute the file according to it’s true filetype instead of it’s extension. Adversaries can hide a program’s true filetype by changing the extension of the file. They can then add a space to the end of the name so that the OS automatically executes the file when it’s double-clicked.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1036-masquerading](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1036-masquerading)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3961]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Masquerading Space After Filename**

In Linux and macOS environments, file execution is determined by the file’s true type rather than its extension. Adversaries exploit this by appending a space to filenames, misleading users into executing malicious files disguised as benign. The detection rule identifies such anomalies by monitoring process creation events with filenames ending in a space, excluding known safe processes and paths, thus highlighting potential masquerading attempts.

**Possible investigation steps**

* Review the process creation event details to identify the full path and name of the executable with a space appended. This can help determine if the file is located in a suspicious or unusual directory.
* Check the process.parent.args field to understand the parent process that initiated the execution. This can provide context on whether the execution was part of a legitimate process chain or potentially malicious activity.
* Investigate the user account associated with the process creation event to determine if the account has a history of executing similar files or if it has been compromised.
* Examine the file’s true type and hash to verify its legitimacy and check against known malicious file databases or threat intelligence sources.
* Look for any additional process events or network activity associated with the suspicious executable to identify potential lateral movement or data exfiltration attempts.
* Cross-reference the event with any recent alerts or incidents involving the same host or user to identify patterns or ongoing threats.

**False positive analysis**

* Processes like "ls", "find", "grep", and "xkbcomp" are known to be safe and can be excluded from triggering the rule by adding them to the exception list.
* Executables located in directories such as "/opt/nessus_agent/**", "/opt/gitlab/sv/gitlab-exporter/**", and "/tmp/ansible-admin/*" are typically non-threatening and should be excluded to prevent false positives.
* Parent processes with arguments like "./check_rubrik", "/usr/bin/check_mk_agent", "/etc/rubrik/start_stop_bootstrap.sh", and "/etc/rubrik/start_stop_agent.sh" are generally safe and can be added to the exclusion list to avoid unnecessary alerts.
* Regularly review and update the exception list to ensure that only verified safe processes and paths are excluded, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution or spread of the potentially malicious file.
* Terminate any suspicious processes identified by the detection rule to halt any ongoing malicious activity.
* Conduct a forensic analysis of the file with the appended space to determine its true file type and origin, using tools like file command or hex editors.
* Remove the malicious file from the system and any other locations it may have been copied to, ensuring complete eradication.
* Review and update endpoint protection settings to block execution of files with suspicious naming conventions, such as those ending with a space.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess potential impacts on other systems.
* Implement additional monitoring for similar masquerading attempts by enhancing logging and alerting mechanisms to detect files with unusual naming patterns.


## Setup [_setup_913]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_4978]

```js
process where host.os.type:("linux","macos") and event.type == "start" and
process.executable regex~ """/[a-z0-9\s_\-\\./]+\s""" and not (
  process.name in ("ls", "find", "grep", "xkbcomp") or
  process.executable like ("/opt/nessus_agent/*", "/opt/gitlab/sv/gitlab-exporter/*", "/tmp/ansible-admin/*") or
  process.parent.args in (
    "./check_rubrik", "/usr/bin/check_mk_agent", "/etc/rubrik/start_stop_bootstrap.sh", "/etc/rubrik/start_stop_agent.sh"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Space after Filename
    * ID: T1036.006
    * Reference URL: [https://attack.mitre.org/techniques/T1036/006/](https://attack.mitre.org/techniques/T1036/006/)



