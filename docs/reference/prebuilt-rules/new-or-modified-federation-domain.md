---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/new-or-modified-federation-domain.html
---

# New or Modified Federation Domain [new-or-modified-federation-domain]

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

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_594]

**Triage and analysis**

[TBC: QUOTE]
**Investigating New or Modified Federation Domain**

Federation domains enable trust between Office 365 and external identity providers, facilitating seamless authentication. Adversaries may exploit this by altering federation settings to redirect authentication flows, potentially gaining unauthorized access. The detection rule monitors specific actions like domain modifications, signaling potential privilege escalation attempts, and alerts analysts to investigate these changes.

**Possible investigation steps**

* Review the event logs for the specific actions listed in the query, such as "Set-AcceptedDomain" or "Add-FederatedDomain", to identify the exact changes made to the federation domain settings.
* Identify the user account associated with the event by examining the event logs, and verify if the account has the necessary permissions to perform such actions.
* Check the event.outcome field to confirm the success of the action and cross-reference with any recent administrative changes or requests to validate legitimacy.
* Investigate the event.provider and event.category fields to ensure the actions were performed through legitimate channels and not via unauthorized or suspicious methods.
* Analyze the timing and frequency of the federation domain changes to detect any unusual patterns or repeated attempts that could indicate malicious activity.
* Correlate the detected changes with any recent alerts or incidents involving privilege escalation or unauthorized access attempts to assess potential links or broader security implications.

**False positive analysis**

* Routine administrative changes to federation domains by IT staff can trigger alerts. To manage this, create exceptions for known and scheduled maintenance activities by trusted administrators.
* Automated scripts or tools used for domain management may cause false positives. Identify these scripts and exclude their actions from triggering alerts by whitelisting their associated accounts or IP addresses.
* Integration of new services or applications that require federation domain modifications can be mistaken for suspicious activity. Document these integrations and adjust the rule to recognize these legitimate changes.
* Changes made during organizational restructuring, such as mergers or acquisitions, might appear as unauthorized modifications. Coordinate with relevant departments to anticipate these changes and temporarily adjust monitoring thresholds or exclusions.
* Regular audits or compliance checks that involve domain settings adjustments can lead to false positives. Schedule these audits and inform the security team to prevent unnecessary alerts.

**Response and remediation**

* Immediately disable any newly added or modified federation domains to prevent unauthorized access. This can be done using the appropriate administrative tools in Office 365.
* Review and revoke any suspicious or unauthorized access tokens or sessions that may have been issued through the compromised federation domain.
* Conduct a thorough audit of recent administrative actions and access logs to identify any unauthorized changes or access patterns related to the federation domain modifications.
* Escalate the incident to the security operations team for further investigation and to determine if additional containment measures are necessary.
* Implement additional monitoring on federation domain settings to detect any further unauthorized changes promptly.
* Communicate with affected stakeholders and provide guidance on any immediate actions they need to take, such as password resets or additional authentication steps.
* Review and update federation domain policies and configurations to ensure they align with best practices and reduce the risk of similar incidents in the future.


## Setup [_setup_382]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_636]

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

    * Name: Domain or Tenant Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Trust Modification
    * ID: T1484.002
    * Reference URL: [https://attack.mitre.org/techniques/T1484/002/](https://attack.mitre.org/techniques/T1484/002/)



