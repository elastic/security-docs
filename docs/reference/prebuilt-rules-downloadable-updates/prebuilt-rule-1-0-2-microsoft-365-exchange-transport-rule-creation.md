---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-microsoft-365-exchange-transport-rule-creation.html
---

# Microsoft 365 Exchange Transport Rule Creation [prebuilt-rule-1-0-2-microsoft-365-exchange-transport-rule-creation]

Identifies a transport rule creation in Microsoft 365. As a best practice, Exchange Online mail transport rules should not be set to forward email to domains outside of your organization. An adversary may create transport rules to exfiltrate data.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-transportrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-transportrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules](https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1449]

## Config

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1680]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
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



