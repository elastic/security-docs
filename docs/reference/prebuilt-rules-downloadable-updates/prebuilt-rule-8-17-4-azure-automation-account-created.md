---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-automation-account-created.html
---

# Azure Automation Account Created [prebuilt-rule-8-17-4-azure-automation-account-created]

Identifies when an Azure Automation account is created. Azure Automation accounts can be used to automate management tasks and orchestrate actions across systems. An adversary may create an Automation account in order to maintain persistence in their target’s environment.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor](https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor)
* [https://github.com/hausec/PowerZure](https://github.com/hausec/PowerZure)
* [https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/](https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4106]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Automation Account Created**

Azure Automation accounts facilitate the automation of management tasks and orchestration across cloud environments, enhancing operational efficiency. However, adversaries may exploit these accounts to establish persistence by automating malicious activities. The detection rule monitors the creation of these accounts by analyzing specific Azure activity logs, focusing on successful operations, to identify potential unauthorized or suspicious account creations.

**Possible investigation steps**

* Review the Azure activity logs to confirm the creation of the Automation account by checking for the operation name "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and ensure the event outcome is marked as Success.
* Identify the user or service principal that initiated the creation of the Automation account by examining the associated user identity information in the activity logs.
* Investigate the context of the Automation account creation by reviewing recent activities performed by the identified user or service principal to determine if there are any other suspicious or unauthorized actions.
* Check the configuration and permissions of the newly created Automation account to ensure it does not have excessive privileges that could be exploited for persistence or lateral movement.
* Correlate the Automation account creation event with other security alerts or logs to identify any patterns or indicators of compromise that may suggest malicious intent.

**False positive analysis**

* Routine administrative tasks may trigger the rule when legitimate users create Azure Automation accounts for operational purposes. To manage this, maintain a list of authorized personnel and their expected activities, and cross-reference alerts with this list.
* Automated deployment scripts or infrastructure-as-code tools might create automation accounts as part of their normal operation. Identify these scripts and exclude their associated activities from triggering alerts by using specific identifiers or tags.
* Scheduled maintenance or updates by cloud service providers could result in the creation of automation accounts. Verify the timing and context of the account creation against known maintenance schedules and exclude these from alerts if they match.
* Development and testing environments often involve frequent creation and deletion of resources, including automation accounts. Implement separate monitoring rules or environments for these non-production areas to reduce noise in alerts.

**Response and remediation**

* Immediately review the Azure activity logs to confirm the creation of the Automation account and identify the user or service principal responsible for the action.
* Disable the newly created Azure Automation account to prevent any potential malicious automation tasks from executing.
* Conduct a thorough investigation of the user or service principal that created the account to determine if their credentials have been compromised or if they have acted maliciously.
* Reset credentials and enforce multi-factor authentication for the identified user or service principal to prevent unauthorized access.
* Review and adjust Azure role-based access control (RBAC) policies to ensure that only authorized personnel have the ability to create Automation accounts.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems or accounts have been compromised.
* Implement enhanced monitoring and alerting for future Automation account creations to quickly detect and respond to similar threats.


## Setup [_setup_993]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5123]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



