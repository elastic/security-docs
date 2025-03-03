---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-microsoft-365-exchange-safe-attachment-rule-disabled.html
---

# Microsoft 365 Exchange Safe Attachment Rule Disabled [prebuilt-rule-1-0-2-microsoft-365-exchange-safe-attachment-rule-disabled]

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

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1447]

## Config

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1678]

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



