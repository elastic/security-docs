---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-resource-group-deletion.html
---

# Azure Resource Group Deletion [azure-resource-group-deletion]

Identifies the deletion of a resource group in Azure, which includes all resources within the group. Deletion is permanent and irreversible. An adversary may delete a resource group in an attempt to evade defenses or intentionally destroy data.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Log Auditing
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_203]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Resource Group Deletion**

Azure Resource Groups are containers that hold related resources for an Azure solution, enabling efficient management and organization. Adversaries may exploit this by deleting entire groups to disrupt services or erase data, causing significant impact. The detection rule monitors Azure activity logs for successful deletion operations, flagging potential malicious actions for further investigation.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by checking for the operation name "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and ensure the event outcome is marked as "Success" or "success".
* Identify the user or service principal responsible for the deletion by examining the associated user identity or service principal ID in the activity logs.
* Check the timestamp of the deletion event to determine when the resource group was deleted and correlate this with any other suspicious activities around the same time.
* Investigate the resources contained within the deleted resource group to assess the potential impact, including any critical services or data that may have been affected.
* Review any recent changes in permissions or roles assigned to the user or service principal involved in the deletion to identify potential privilege escalation or misuse.
* Examine any related alerts or logs for unusual activities or patterns that might indicate a broader attack or compromise within the Azure environment.

**False positive analysis**

* Routine maintenance activities by IT teams may trigger alerts when resource groups are intentionally deleted as part of regular updates or infrastructure changes. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or deployment tools that manage resource lifecycles might delete resource groups as part of their normal operation. Identify these scripts and exclude their activity from alerts by filtering based on the service principal or automation account used.
* Testing environments often involve frequent creation and deletion of resource groups. Exclude these environments from alerts by tagging them appropriately and configuring the detection rule to ignore actions on tagged resources.
* Mergers or organizational restructuring can lead to legitimate resource group deletions. Coordinate with relevant departments to anticipate these changes and temporarily adjust monitoring rules to prevent false positives.
* Ensure that any third-party services or consultants with access to your Azure environment are accounted for, as their activities might include resource group deletions. Establish clear communication channels to verify their actions and adjust monitoring rules accordingly.

**Response and remediation**

* Immediately isolate the affected Azure subscription to prevent further unauthorized actions. This can be done by temporarily disabling access or applying strict access controls.
* Review and revoke any suspicious or unauthorized access permissions associated with the affected resource group to prevent further exploitation.
* Restore the deleted resources from backups if available. Ensure that backup and recovery processes are validated and functioning correctly.
* Conduct a thorough audit of recent Azure activity logs to identify any other potentially malicious actions or compromised accounts.
* Escalate the incident to the security operations team for a detailed investigation and to determine if there are broader implications or related threats.
* Implement additional monitoring and alerting for similar deletion activities across all Azure subscriptions to enhance early detection of such threats.
* Review and strengthen access management policies, ensuring that only authorized personnel have the necessary permissions to delete resource groups.


## Setup [_setup_138]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_208]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



