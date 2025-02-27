---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-automation-runbook-deleted.html
---

# Azure Automation Runbook Deleted [prebuilt-rule-8-17-4-azure-automation-runbook-deleted]

Identifies when an Azure Automation runbook is deleted. An adversary may delete an Azure Automation runbook in order to disrupt their target’s automated business operations or to remove a malicious runbook for defense evasion.

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

* [https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor](https://powerzure.readthedocs.io/en/latest/Functions/operational.md#create-backdoor)
* [https://github.com/hausec/PowerZure](https://github.com/hausec/PowerZure)
* [https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/](https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4090]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Automation Runbook Deleted**

Azure Automation Runbooks automate repetitive tasks in cloud environments, enhancing operational efficiency. Adversaries may exploit this by deleting runbooks to disrupt operations or conceal malicious activities. The detection rule monitors Azure activity logs for successful runbook deletions, signaling potential defense evasion tactics, and alerts analysts to investigate further.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by checking the operation name "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and ensure the event outcome is marked as Success.
* Identify the user or service principal responsible for the deletion by examining the associated user identity information in the activity logs.
* Investigate the timeline of events leading up to and following the runbook deletion to identify any suspicious activities or patterns, such as unauthorized access attempts or changes to other resources.
* Check for any recent modifications or unusual activities in the affected Azure Automation account to determine if there are other signs of compromise or tampering.
* Assess the impact of the deleted runbook on business operations and determine if any critical automation processes were disrupted.
* If applicable, review any available backup or version history of the deleted runbook to restore it and mitigate operational disruptions.

**False positive analysis**

* Routine maintenance activities by IT staff may lead to legitimate runbook deletions. To manage this, create exceptions for known maintenance periods or specific user accounts responsible for these tasks.
* Automated scripts or third-party tools that manage runbooks might trigger deletions as part of their normal operation. Identify these tools and exclude their activity from alerts by filtering based on their service accounts or IP addresses.
* Organizational policy changes or cloud environment restructuring can result in planned runbook deletions. Document these changes and adjust the detection rule to exclude these events by correlating with change management records.
* Test environments often involve frequent creation and deletion of runbooks. Exclude these environments from alerts by using tags or specific resource group identifiers associated with non-production environments.

**Response and remediation**

* Immediately isolate the affected Azure Automation account to prevent further unauthorized deletions or modifications of runbooks.
* Review the Azure activity logs to identify the user or service principal responsible for the deletion and revoke their access if unauthorized.
* Restore the deleted runbook from backups or version control if available, ensuring that the restored version is free from any malicious modifications.
* Conduct a security review of all remaining runbooks to ensure they have not been tampered with or contain malicious code.
* Implement stricter access controls and auditing for Azure Automation accounts, ensuring that only authorized personnel have the ability to delete runbooks.
* Escalate the incident to the security operations team for further investigation and to determine if additional malicious activities have occurred.
* Enhance monitoring and alerting for similar activities by integrating additional context or indicators from the MITRE ATT&CK framework related to defense evasion tactics.


## Setup [_setup_977]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5107]

```js
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and
    event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



