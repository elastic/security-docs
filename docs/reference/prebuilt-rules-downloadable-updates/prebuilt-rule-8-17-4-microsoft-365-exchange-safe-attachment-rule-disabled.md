---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-365-exchange-safe-attachment-rule-disabled.html
---

# Microsoft 365 Exchange Safe Attachment Rule Disabled [prebuilt-rule-8-17-4-microsoft-365-exchange-safe-attachment-rule-disabled]

Identifies when a safe attachment rule is disabled in Microsoft 365. Safe attachment rules can extend malware protections to include routing all messages and attachments without a known malware signature to a special hypervisor environment. An adversary or insider threat may disable a safe attachment rule to exfiltrate data or evade defenses.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/exchange/disable-safeattachmentrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/disable-safeattachmentrule?view=exchange-ps)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4222]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Exchange Safe Attachment Rule Disabled**

Microsoft 365’s Safe Attachment feature enhances security by analyzing email attachments in a secure environment to detect unknown malware. Disabling this rule can expose organizations to threats by allowing potentially harmful attachments to bypass scrutiny. Adversaries may exploit this to exfiltrate data or avoid detection. The detection rule monitors audit logs for successful attempts to disable this feature, signaling potential defense evasion activities.

**Possible investigation steps**

* Review the audit logs for the specific event.action "Disable-SafeAttachmentRule" to identify the user or account responsible for the action.
* Check the event.outcome field to confirm the success of the rule being disabled and gather additional context from related logs around the same timestamp.
* Investigate the event.provider "Exchange" to determine if there are any other recent suspicious activities or changes made by the same user or account.
* Assess the event.category "web" to understand if there were any web-based interactions or anomalies that coincide with the disabling of the safe attachment rule.
* Evaluate the risk score and severity to prioritize the investigation and determine if immediate action is required to mitigate potential threats.
* Cross-reference the identified user or account with known insider threat indicators or previous security incidents to assess the likelihood of malicious intent.

**False positive analysis**

* Routine administrative changes can trigger alerts when IT staff disable Safe Attachment rules for legitimate reasons, such as testing or maintenance. To manage this, create exceptions for known administrative accounts or scheduled maintenance windows.
* Automated scripts or third-party tools used for email management might disable Safe Attachment rules as part of their operations. Identify these tools and exclude their actions from triggering alerts by whitelisting their associated accounts or IP addresses.
* Changes in organizational policy or security configurations might necessitate temporary disabling of Safe Attachment rules. Document these policy changes and adjust the monitoring rules to account for these temporary exceptions.
* Training or onboarding sessions for new IT staff might involve disabling Safe Attachment rules as part of learning exercises. Ensure these activities are logged and excluded from alerts by setting up temporary exceptions for training periods.

**Response and remediation**

* Immediately re-enable the Safe Attachment Rule in Microsoft 365 to restore the security posture and prevent further exposure to potentially harmful attachments.
* Conduct a thorough review of recent email logs and quarantine any suspicious attachments that were delivered during the period the rule was disabled.
* Isolate any systems or accounts that interacted with suspicious attachments to prevent potential malware spread or data exfiltration.
* Escalate the incident to the security operations team for further investigation and to determine if there was any unauthorized access or data compromise.
* Implement additional monitoring on the affected accounts and systems to detect any signs of ongoing or further malicious activity.
* Review and update access controls and permissions to ensure that only authorized personnel can modify security rules and configurations.
* Conduct a post-incident analysis to identify the root cause and implement measures to prevent similar incidents, such as enhancing alerting mechanisms for critical security rule changes.


## Setup [_setup_1083]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5220]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeAttachmentRule" and event.outcome:success
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



