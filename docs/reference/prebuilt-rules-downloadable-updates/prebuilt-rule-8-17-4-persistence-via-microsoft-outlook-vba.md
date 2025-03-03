---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-persistence-via-microsoft-outlook-vba.html
---

# Persistence via Microsoft Outlook VBA [prebuilt-rule-8-17-4-persistence-via-microsoft-outlook-vba]

Detects attempts to establish persistence on an endpoint by installing a rogue Microsoft Outlook VBA Template.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/](https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/)
* [https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/](https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 308

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4915]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Microsoft Outlook VBA**

Microsoft Outlook supports VBA scripting to automate tasks, which can be exploited by adversaries to maintain persistence. Attackers may install malicious VBA templates in the Outlook environment, triggering scripts upon application startup. The detection rule identifies suspicious activity by monitoring for unauthorized modifications to the VBAProject.OTM file, a common target for such persistence techniques, leveraging various data sources to flag potential threats.

**Possible investigation steps**

* Review the alert details to confirm the file path matches the pattern "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM" and ensure the event type is not "deletion".
* Check the modification timestamp of the VbaProject.OTM file to determine when the unauthorized change occurred.
* Identify the user account associated with the file path to understand which user profile was potentially compromised.
* Investigate recent login activities and processes executed by the identified user to detect any anomalies or unauthorized access.
* Examine the contents of the VbaProject.OTM file for any suspicious or unfamiliar VBA scripts that could indicate malicious intent.
* Correlate the findings with other data sources such as Sysmon, Microsoft Defender for Endpoint, or SentinelOne to gather additional context or related events.
* Assess the risk and impact of the detected activity and determine if further containment or remediation actions are necessary.

**False positive analysis**

* Routine updates or legitimate changes to the Outlook environment can trigger alerts. Users should verify if recent software updates or administrative changes align with the detected activity.
* Custom scripts or macros developed by IT departments for legitimate automation tasks may be flagged. Establish a whitelist of known and approved VBA scripts to prevent unnecessary alerts.
* User-initiated actions such as importing or exporting Outlook settings might modify the VbaProject.OTM file. Educate users on the implications of these actions and consider excluding these specific user actions from triggering alerts.
* Security software or backup solutions that interact with Outlook files could cause false positives. Identify and exclude these processes if they are known to be safe and necessary for operations.
* Regularly review and update the exclusion list to ensure it reflects current organizational needs and does not inadvertently allow malicious activity.

**Response and remediation**

* Isolate the affected endpoint from the network to prevent further spread of the malicious VBA script and to contain the threat.
* Terminate any suspicious Outlook processes on the affected machine to stop the execution of potentially harmful scripts.
* Remove the unauthorized or malicious VbaProject.OTM file from the affected user’s Outlook directory to eliminate the persistence mechanism.
* Restore the VbaProject.OTM file from a known good backup if available, ensuring that it is free from any unauthorized modifications.
* Conduct a full antivirus and antimalware scan on the affected endpoint using tools like Microsoft Defender for Endpoint to identify and remove any additional threats.
* Review and update endpoint security policies to restrict unauthorized modifications to Outlook VBA files, leveraging application whitelisting or similar controls.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_5870]

```js
file where host.os.type == "windows" and event.type != "deletion" and
 file.path : "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)



