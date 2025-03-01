---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-microsoft-365-inbox-forwarding-rule-created.html
---

# Microsoft 365 Inbox Forwarding Rule Created [prebuilt-rule-8-2-1-microsoft-365-inbox-forwarding-rule-created]

Identifies when a new Inbox forwarding rule is created in Microsoft 365. Inbox rules process messages in the Inbox based on conditions and take actions. In this case, the rules will forward the emails to a defined address. Attackers can abuse Inbox Rules to intercept and exfiltrate email data without making organization-wide configuration changes or having the corresponding privileges.

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

* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account?view=o365-worldwide)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide)
* [https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/Extractor%20Cheat%20Sheet.pdf](https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/Extractor%20Cheat%20Sheet.pdf)

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
* Gary Blackwell
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1969]



## Rule query [_rule_query_2254]

```js
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:"New-InboxRule" and
    (
        o365.audit.Parameters.ForwardTo:* or
        o365.audit.Parameters.ForwardAsAttachmentTo:* or
        o365.audit.Parameters.RedirectTo:*
    )
    and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Email Forwarding Rule
    * ID: T1114.003
    * Reference URL: [https://attack.mitre.org/techniques/T1114/003/](https://attack.mitre.org/techniques/T1114/003/)



