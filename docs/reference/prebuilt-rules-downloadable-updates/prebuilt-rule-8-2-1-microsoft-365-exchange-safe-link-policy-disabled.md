---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-microsoft-365-exchange-safe-link-policy-disabled.html
---

# Microsoft 365 Exchange Safe Link Policy Disabled [prebuilt-rule-8-2-1-microsoft-365-exchange-safe-link-policy-disabled]

Identifies when a Safe Link policy is disabled in Microsoft 365. Safe Link policies for Office applications extend phishing protection to documents that contain hyperlinks, even after they have been delivered to a user.

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

* [https://docs.microsoft.com/en-us/powershell/module/exchange/disable-safelinksrule?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/disable-safelinksrule?view=exchange-ps)
* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/atp-safe-links?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/atp-safe-links?view=o365-worldwide)

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1984]



## Rule query [_rule_query_2269]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeLinksRule" and event.outcome:success
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



