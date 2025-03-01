---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-teams-guest-access-enabled.html
---

# Microsoft 365 Teams Guest Access Enabled [microsoft-365-teams-guest-access-enabled]

Identifies when guest access is enabled in Microsoft Teams. Guest access in Teams allows people outside the organization to access teams and channels. An adversary may enable guest access to maintain persistence in an environment.

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

* [https://docs.microsoft.com/en-us/powershell/module/skype/get-csteamsclientconfiguration?view=skype-ps](https://docs.microsoft.com/en-us/powershell/module/skype/get-csteamsclientconfiguration?view=skype-ps)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_522]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Teams Guest Access Enabled**

Microsoft Teams allows organizations to collaborate with external users through guest access, facilitating communication and teamwork. However, adversaries can exploit this feature to gain persistent access to sensitive environments by enabling guest access without authorization. The detection rule monitors audit logs for specific configurations that indicate guest access has been enabled, helping identify unauthorized changes and potential security breaches.

**Possible investigation steps**

* Review the audit logs to confirm the event.action "Set-CsTeamsClientConfiguration" was successfully executed with the parameter o365.audit.Parameters.AllowGuestUser set to True.
* Identify the user account responsible for enabling guest access by examining the event logs for the user ID or account name associated with the action.
* Check the user’s activity history to determine if there are any other suspicious actions or patterns, such as changes to other configurations or unusual login times.
* Investigate the context of the change by reviewing any related communications or requests that might justify enabling guest access, ensuring it aligns with organizational policies.
* Assess the potential impact by identifying which teams and channels now have guest access enabled and evaluate the sensitivity of the information accessible to external users.
* Contact the user or their manager to verify if the change was authorized and necessary, and document their response for future reference.

**False positive analysis**

* Legitimate collaboration with external partners may trigger alerts when guest access is enabled for business purposes. To manage this, create exceptions for known and approved external domains or specific projects that require guest access.
* Routine administrative actions by IT staff to enable guest access for specific teams or channels can be mistaken for unauthorized changes. Implement a process to log and approve such changes internally, and exclude these from triggering alerts.
* Automated scripts or third-party applications that configure Teams settings, including guest access, might cause false positives. Identify and whitelist these scripts or applications to prevent unnecessary alerts.
* Changes made during scheduled maintenance windows can be misinterpreted as unauthorized. Define and exclude these time periods from monitoring to reduce false positives.

**Response and remediation**

* Immediately disable guest access in Microsoft Teams by updating the Teams client configuration to prevent unauthorized external access.
* Conduct a thorough review of recent audit logs to identify any unauthorized changes or suspicious activities related to guest access settings.
* Notify the security team and relevant stakeholders about the potential breach to ensure awareness and initiate further investigation.
* Revoke any unauthorized guest accounts that have been added to Teams to eliminate potential persistence mechanisms.
* Implement additional monitoring on Teams configurations to detect any future unauthorized changes to guest access settings.
* Escalate the incident to the organization’s incident response team for a comprehensive investigation and to determine if further containment actions are necessary.
* Review and update access control policies to ensure that enabling guest access requires appropriate authorization and oversight.


## Setup [_setup_345]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_561]

```js
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTeamsClientConfiguration" and
o365.audit.Parameters.AllowGuestUser:True and event.outcome:success
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



