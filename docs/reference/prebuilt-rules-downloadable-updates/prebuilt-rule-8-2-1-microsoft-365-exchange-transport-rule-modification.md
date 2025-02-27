---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-microsoft-365-exchange-transport-rule-modification.html
---

# Microsoft 365 Exchange Transport Rule Modification [prebuilt-rule-8-2-1-microsoft-365-exchange-transport-rule-modification]

Identifies when a transport rule has been disabled or deleted in Microsoft 365. Mail flow rules (also known as transport rules) are used to identify and take action on messages that flow through your organization. An adversary or insider threat may modify a transport rule to exfiltrate data or evade defenses.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-transportrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/disable-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/disable-transportrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1979]



## Rule query [_rule_query_2264]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



