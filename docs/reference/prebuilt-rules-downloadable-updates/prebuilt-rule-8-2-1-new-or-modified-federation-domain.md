---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-new-or-modified-federation-domain.html
---

# New or Modified Federation Domain [prebuilt-rule-8-2-1-new-or-modified-federation-domain]

Identifies a new or modified federation domain, which can be used to create a trust between O365 and an external identity provider.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-accepteddomain?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-accepteddomain?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/remove-federateddomain?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-federateddomain?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-accepteddomain?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-accepteddomain?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/add-federateddomain?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/add-federateddomain?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/set-accepteddomain?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/set-accepteddomain?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/msonline/set-msoldomainfederationsettings?view=azureadps-1.0](https://docs.microsoft.com/en-us/powershell/module/msonline/set-msoldomainfederationsettings?view=azureadps-1.0)

**Tags**:

* Elastic
* Cloud
* Microsoft 365
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 4

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1996]



## Rule query [_rule_query_2281]

```js
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Set-AcceptedDomain" or
"Set-MsolDomainFederationSettings" or "Add-FederatedDomain" or "New-AcceptedDomain" or "Remove-AcceptedDomain" or "Remove-FederatedDomain") and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Domain Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Domain Trust Modification
    * ID: T1484.002
    * Reference URL: [https://attack.mitre.org/techniques/T1484/002/](https://attack.mitre.org/techniques/T1484/002/)



