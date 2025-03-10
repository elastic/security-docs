---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-first-time-seen-newcredentials-logon-process.html
---

# First Time Seen NewCredentials Logon Process [prebuilt-rule-8-17-4-first-time-seen-newcredentials-logon-process]

Identifies a new credentials logon type performed by an unusual process. This may indicate the existence of an access token forging capability that are often abused to bypass access control restrictions.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/pt/blog/how-attackers-abuse-access-token-manipulation](https://www.elastic.co/pt/blog/how-attackers-abuse-access-token-manipulation)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: System
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4966]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Time Seen NewCredentials Logon Process**

The NewCredentials logon type in Windows allows processes to impersonate a user without requiring a new logon session, often used for legitimate tasks like network resource access. However, adversaries can exploit this by forging access tokens to escalate privileges and bypass controls. The detection rule identifies unusual processes performing this logon type, excluding known system paths and service accounts, to flag potential misuse indicative of token manipulation attacks.

**Possible investigation steps**

* Review the process executable path to determine if it is a known or expected application, especially since the query excludes common system paths like Program Files.
* Investigate the SubjectUserName to identify the user account associated with the logon event and determine if it is a legitimate user or a potential compromised account.
* Check the historical activity of the identified process and user account to see if this behavior is consistent with past actions or if it is anomalous.
* Correlate the event with other security logs to identify any preceding or subsequent suspicious activities, such as failed logon attempts or unusual network connections.
* Assess the environment for any recent changes or incidents that might explain the unusual logon process, such as software updates or new application deployments.
* Consult threat intelligence sources to determine if the process or behavior is associated with known malicious activity or threat actors.

**False positive analysis**

* Legitimate administrative tools or scripts may trigger this rule if they use the NewCredentials logon type for network resource access. To manage this, identify and whitelist these tools by their process executable paths.
* Scheduled tasks or automated processes running under service accounts might be flagged. Review these tasks and exclude them by adding exceptions for known service account names.
* Software updates or installations that require elevated privileges could cause false positives. Monitor these activities and create exceptions for the specific processes involved in regular update cycles.
* Custom in-house applications that use impersonation for legitimate purposes may be detected. Work with development teams to document these applications and exclude their process paths from the rule.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified as using the NewCredentials logon type that are not part of known system paths or service accounts.
* Revoke any potentially compromised access tokens and reset credentials for affected user accounts to prevent further misuse.
* Conduct a thorough review of recent logon events and process executions on the affected system to identify any additional unauthorized activities or compromised accounts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring for similar suspicious logon activities across the network to detect and respond to potential future attempts promptly.
* Review and update access control policies and token management practices to mitigate the risk of access token manipulation in the future.


## Rule query [_rule_query_5921]

```js
event.category:"authentication" and host.os.type:"windows" and winlog.logon.type:"NewCredentials" and winlog.event_data.LogonProcessName:(Advapi* or "Advapi  ") and not winlog.event_data.SubjectUserName:*$ and not process.executable :???\\Program?Files*
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

* Sub-technique:

    * Name: Token Impersonation/Theft
    * ID: T1134.001
    * Reference URL: [https://attack.mitre.org/techniques/T1134/001/](https://attack.mitre.org/techniques/T1134/001/)



