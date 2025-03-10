---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-exchange-anti-phish-policy-deletion.html
---

# Microsoft 365 Exchange Anti-Phish Policy Deletion [microsoft-365-exchange-anti-phish-policy-deletion]

Identifies the deletion of an anti-phishing policy in Microsoft 365. By default, Microsoft 365 includes built-in features that help protect users from phishing attacks. Anti-phishing polices increase this protection by refining settings to better detect and prevent attacks.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-antiphishpolicy?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-antiphishpolicy?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_504]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Anti-Phish Policy Deletion**

Microsoft 365’s anti-phishing policies enhance security by fine-tuning detection settings to thwart phishing attacks. Adversaries may delete these policies to weaken defenses, facilitating unauthorized access. The detection rule monitors audit logs for successful deletions of anti-phishing policies, signaling potential malicious activity by identifying specific actions and outcomes associated with policy removal.

**Possible investigation steps**

* Review the audit logs for the specific event.action "Remove-AntiPhishPolicy" to identify the user account responsible for the deletion.
* Check the event.outcome field to confirm the success of the policy deletion and gather additional context from related logs around the same timestamp.
* Investigate the user account’s recent activities in Microsoft 365 to identify any other suspicious actions or anomalies, such as unusual login locations or times.
* Assess whether the user account has been compromised by checking for any unauthorized access attempts or changes in account settings.
* Evaluate the impact of the deleted anti-phishing policy by reviewing the organization’s current phishing protection measures and any recent phishing incidents.
* Coordinate with the IT security team to determine if the policy deletion was authorized or part of a legitimate change management process.

**False positive analysis**

* Routine administrative actions may trigger the rule if IT staff regularly update or remove outdated anti-phishing policies. To manage this, create exceptions for known administrative accounts performing these actions.
* Scheduled policy reviews might involve the removal of policies as part of a legitimate update process. Document these schedules and exclude them from triggering alerts by setting time-based exceptions.
* Automated scripts used for policy management can inadvertently cause false positives. Identify and whitelist these scripts to prevent unnecessary alerts.
* Changes in organizational policy that require the removal of certain anti-phishing policies can be mistaken for malicious activity. Ensure that such changes are communicated and logged, and adjust the rule to recognize these legitimate actions.
* Test environments where policies are frequently added and removed for validation purposes can generate false positives. Exclude these environments from the rule to avoid confusion.

**Response and remediation**

* Immediately isolate the affected user accounts and systems to prevent further unauthorized access or data exfiltration.
* Recreate the deleted anti-phishing policy using the latest security guidelines and ensure it is applied across all relevant user groups.
* Conduct a thorough review of recent email activity and logs for the affected accounts to identify any phishing emails that may have bypassed security measures.
* Reset passwords for affected accounts and enforce multi-factor authentication (MFA) to enhance account security.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Escalate the incident to the incident response team if there is evidence of broader compromise or if sensitive data has been accessed.
* Implement enhanced monitoring and alerting for similar actions in the future to quickly detect and respond to any further attempts to delete security policies.


## Setup [_setup_329]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_543]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-AntiPhishPolicy" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)



