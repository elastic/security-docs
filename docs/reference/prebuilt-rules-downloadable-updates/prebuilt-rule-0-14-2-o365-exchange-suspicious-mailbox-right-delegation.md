---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-o365-exchange-suspicious-mailbox-right-delegation.html
---

# O365 Exchange Suspicious Mailbox Right Delegation [prebuilt-rule-0-14-2-o365-exchange-suspicious-mailbox-right-delegation]

Identifies the assignment of rights to accesss content from another mailbox. An adversary may use the compromised account to send messages to other accounts in the network of the target business while creating inbox rules, so messages can evade spam/phishing detection mechanisms.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 1

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1296]

## Config

The Microsoft 365 Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1394]

```js
event.dataset:o365.audit and event.provider:Exchange and event.action:Add-MailboxPermission and
o365.audit.Parameters.AccessRights:(FullAccess or SendAs or SendOnBehalf) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Exchange Email Delegate Permissions
    * ID: T1098.002
    * Reference URL: [https://attack.mitre.org/techniques/T1098/002/](https://attack.mitre.org/techniques/T1098/002/)



