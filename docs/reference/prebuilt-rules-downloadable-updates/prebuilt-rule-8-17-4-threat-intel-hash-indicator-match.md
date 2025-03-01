---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-threat-intel-hash-indicator-match.html
---

# Threat Intel Hash Indicator Match [prebuilt-rule-8-17-4-threat-intel-hash-indicator-match]

This rule is triggered when a hash indicator from the Threat Intel Filebeat module or integrations has a match against an event that contains file hashes, such as antivirus alerts, process creation, library load, and file operation events.

**Rule type**: threat_match

**Rule indices**:

* auditbeat-*
* endgame-*
* filebeat-*
* logs-*
* winlogbeat-*

**Severity**: critical

**Risk score**: 99

**Runs every**: 1h

**Searches indices from**: now-65m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-threatintel.md](beats://docs/reference/filebeat/filebeat-module-threatintel.md)
* [docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md](docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md)
* [https://www.elastic.co/security/tip](https://www.elastic.co/security/tip)

**Tags**:

* OS: Windows
* Data Source: Elastic Endgame
* Rule Type: Threat Match
* Resources: Investigation Guide

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4680]

**Triage and analysis**

**Investigating Threat Intel Hash Indicator Match**

Threat Intel indicator match rules allow matching from a local observation, such as an endpoint event that records a file hash with an entry of a file hash stored within the Threat Intel integrations index.

Matches are based on threat intelligence data that’s been ingested during the last 30 days. Some integrations don’t place expiration dates on their threat indicators, so we strongly recommend validating ingested threat indicators and reviewing match results. When reviewing match results, check associated activity to determine whether the event requires additional investigation.

This rule is triggered when a hash indicator from the Threat Intel Filebeat module or an indicator ingested from a threat intelligence integration matches against an event that contains file hashes, such as antivirus alerts, file operation events, etc.

[TBC: QUOTE]
**Possible investigation steps**

* Gain context about the field that matched the local observation. This information can be found in the `threat.indicator.matched.field` field.
* Investigate the hash , which can be found in the `threat.indicator.matched.atomic` field:
* Search for the existence and reputation of the hash in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Scope other potentially compromised hosts in your environment by mapping hosts with file operations involving the same hash.
* Identify the process that created the file.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Enrich the information that you have right now by determining how the file was dropped, where it was downloaded from, etc. This can help you determine if the event is part of an ongoing campaign against the organization.
* Retrieve the involved file and examine the host for derived artifacts that indicate suspicious activities:
* Analyze the process executable using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Using the data collected through the analysis, scope users targeted and other machines infected in the environment.

**False Positive Analysis**

* Adversaries often use legitimate tools as network administrators, such as `PsExec` or `AdFind`. These tools are often included in indicator lists, which creates the potential for false positives.

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1495]

**Setup**

This rule needs threat intelligence indicators to work. Threat intelligence indicators can be collected using an [Elastic Agent integration](docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md#agent-ti-integration), the [Threat Intel module](docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md#ti-mod-integration), or a [custom integration](docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md#custom-ti-integration).

More information can be found [here](docs-content://solutions/security/get-started/enable-threat-intelligence-integrations.md).


## Rule query [_rule_query_5635]

```js
file.hash.*:* or process.hash.*:* or dll.hash.*:*
```


