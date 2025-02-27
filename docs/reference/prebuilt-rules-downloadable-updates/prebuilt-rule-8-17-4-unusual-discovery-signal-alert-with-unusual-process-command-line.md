---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-discovery-signal-alert-with-unusual-process-command-line.html
---

# Unusual Discovery Signal Alert with Unusual Process Command Line [prebuilt-rule-8-17-4-unusual-discovery-signal-alert-with-unusual-process-command-line]

This rule leverages alert data from various Discovery building block rules to alert on signals with unusual unique host.id, user.id and process.command_line entries.

**Rule type**: new_terms

**Rule indices**:

* .alerts-security.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: Higher-Order Rule
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4829]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Discovery Signal Alert with Unusual Process Command Line**

This detection rule identifies anomalies in process command lines on Windows systems, which may indicate adversarial reconnaissance activities. Attackers often exploit legitimate discovery tools to gather system information stealthily. By monitoring unique combinations of host, user, and command line data, the rule flags deviations from normal behavior, helping analysts pinpoint potential threats early.

**Possible investigation steps**

* Review the alert details to identify the specific host.id, user.id, and process.command_line that triggered the alert. This will help in understanding the context of the anomaly.
* Check the historical activity of the identified host.id and user.id to determine if the process.command_line has been executed previously and assess if this behavior is truly unusual.
* Investigate the process.command_line for any known malicious patterns or suspicious commands that could indicate reconnaissance or other adversarial activities.
* Correlate the alert with other security events or logs from the same host or user around the same time to identify any additional suspicious activities or patterns.
* Consult threat intelligence sources to see if the process.command_line or any associated indicators have been reported in recent threat campaigns or advisories.
* If necessary, isolate the affected host to prevent potential lateral movement or further compromise while the investigation is ongoing.

**False positive analysis**

* Legitimate administrative tools may trigger alerts when used by IT staff for routine system checks. To manage this, create exceptions for known safe tools and processes frequently used by trusted users.
* Automated scripts or scheduled tasks that perform regular system audits can be flagged as unusual. Identify these scripts and add them to an allowlist to prevent unnecessary alerts.
* Software updates or installations that involve system discovery commands might be misidentified as threats. Monitor update schedules and exclude related processes during these times.
* Security software performing scans or inventory checks can mimic adversarial reconnaissance. Verify the processes associated with these tools and configure the rule to ignore them.
* New software deployments or changes in system configurations may temporarily alter normal command line behavior. Document these changes and adjust the rule settings to accommodate expected deviations.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement or data exfiltration. Disconnect it from the network while maintaining power to preserve volatile data for forensic analysis.
* Terminate any suspicious processes identified by the alert, especially those with unusual command lines, to halt any ongoing malicious activity.
* Conduct a thorough review of the affected user’s account for any unauthorized access or privilege escalation. Reset passwords and revoke any unnecessary permissions.
* Analyze the command line arguments and process execution context to understand the scope and intent of the reconnaissance activity. This may involve reviewing logs and correlating with other security events.
* Restore the affected system from a known good backup if any malicious changes or persistence mechanisms are detected. Ensure the backup is free from compromise.
* Update endpoint protection and intrusion detection systems with the latest threat intelligence to enhance detection capabilities against similar reconnaissance activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the activity is part of a larger attack campaign.


## Rule query [_rule_query_5784]

```js
host.os.type:windows and event.kind:signal and kibana.alert.rule.rule_id:(
  "d68e95ad-1c82-4074-a12a-125fe10ac8ba" or "7b8bfc26-81d2-435e-965c-d722ee397ef1" or
  "0635c542-1b96-4335-9b47-126582d2c19a" or "6ea55c81-e2ba-42f2-a134-bccf857ba922" or
  "e0881d20-54ac-457f-8733-fe0bc5d44c55" or "06568a02-af29-4f20-929c-f3af281e41aa" or
  "c4e9ed3e-55a2-4309-a012-bc3c78dad10a" or "51176ed2-2d90-49f2-9f3d-17196428b169"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)



