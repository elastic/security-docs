---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-365-exchange-anti-phish-rule-modification.html
---

# Microsoft 365 Exchange Anti-Phish Rule Modification [prebuilt-rule-8-17-4-microsoft-365-exchange-anti-phish-rule-modification]

Identifies the modification of an anti-phishing rule in Microsoft 365. By default, Microsoft 365 includes built-in features that help protect users from phishing attacks. Anti-phishing rules increase this protection by refining settings to better detect and prevent attacks.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-antiphishrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-antiphishrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/disable-antiphishrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/disable-antiphishrule?view=exchange-ps)

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

## Investigation guide [_investigation_guide_4230]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Anti-Phish Rule Modification**

Microsoft 365’s anti-phishing rules are crucial for safeguarding users against phishing attacks by enhancing detection and prevention settings. Adversaries may attempt to modify or disable these rules to facilitate phishing campaigns, gaining unauthorized access. The detection rule monitors for successful modifications or disabling of anti-phishing rules, signaling potential malicious activity by tracking specific actions within the Exchange environment.

**Possible investigation steps**

* Review the event logs for entries with event.dataset set to o365.audit and event.provider set to Exchange to confirm the context of the alert.
* Check the event.action field for "Remove-AntiPhishRule" or "Disable-AntiPhishRule" to identify the specific action taken on the anti-phishing rule.
* Verify the event.outcome field to ensure the action was successful, indicating a potential security concern.
* Identify the user or account associated with the modification by examining the relevant user fields in the event log.
* Investigate the user’s recent activity and access patterns to determine if there are any other suspicious actions or anomalies.
* Assess the impact of the rule modification by reviewing any subsequent phishing attempts or security incidents that may have occurred.
* Consider reverting the changes to the anti-phishing rule and implementing additional security measures if unauthorized access is confirmed.

**False positive analysis**

* Administrative changes: Legitimate administrative tasks may involve modifying or disabling anti-phishing rules for testing or configuration purposes. To manage this, create exceptions for known administrative accounts or scheduled maintenance windows.
* Security audits: Regular security audits might require temporary adjustments to anti-phishing rules. Document these activities and exclude them from alerts by correlating with audit logs.
* Third-party integrations: Some third-party security tools may interact with Microsoft 365 settings, triggering rule modifications. Identify these tools and exclude their actions from triggering alerts by using their specific identifiers.
* Policy updates: Organizational policy changes might necessitate updates to anti-phishing rules. Ensure these changes are documented and exclude them from alerts by associating them with approved change management processes.

**Response and remediation**

* Immediately isolate the affected user accounts to prevent further unauthorized access and potential spread of phishing attacks.
* Revert any unauthorized changes to the anti-phishing rules by restoring them to their previous configurations using backup or documented settings.
* Conduct a thorough review of recent email logs and user activity to identify any potential phishing emails that may have bypassed the modified rules and take steps to quarantine or delete them.
* Notify the security team and relevant stakeholders about the incident, providing details of the rule modification and any identified phishing attempts.
* Escalate the incident to the incident response team for further investigation and to determine if additional systems or data have been compromised.
* Implement enhanced monitoring and alerting for any further attempts to modify anti-phishing rules, ensuring that similar activities are detected promptly.
* Review and update access controls and permissions for administrative actions within Microsoft 365 to ensure that only authorized personnel can modify security settings.


## Setup [_setup_1091]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5228]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-AntiPhishRule" or "Disable-AntiPhishRule") and event.outcome:success
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



