---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-event-hub-deletion.html
---

# Azure Event Hub Deletion [prebuilt-rule-8-17-4-azure-event-hub-deletion]

Identifies an Event Hub deletion in Azure. An Event Hub is an event processing service that ingests and processes large volumes of events and data. An adversary may delete an Event Hub in an attempt to evade detection.

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

* [https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about)
* [https://azure.microsoft.com/en-in/services/event-hubs/](https://azure.microsoft.com/en-in/services/event-hubs/)
* [https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Log Auditing
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4093]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Event Hub Deletion**

Azure Event Hub is a scalable data streaming platform and event ingestion service, crucial for processing large volumes of data in real-time. Adversaries may target Event Hubs to delete them, aiming to disrupt data flow and evade detection by erasing evidence of their activities. The detection rule monitors Azure activity logs for successful deletion operations, flagging potential defense evasion attempts by identifying unauthorized or suspicious deletions.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by checking the operation name "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and ensure the event outcome is marked as Success.
* Identify the user or service principal responsible for the deletion by examining the associated user identity or service principal ID in the activity logs.
* Investigate the context of the deletion by reviewing recent activities performed by the identified user or service principal to determine if there are any other suspicious actions.
* Check for any recent changes in permissions or roles assigned to the user or service principal to assess if the deletion was authorized or if there was a potential privilege escalation.
* Correlate the deletion event with other security alerts or incidents in the environment to identify if this action is part of a larger attack pattern or campaign.
* Communicate with relevant stakeholders or teams to verify if the deletion was part of a planned operation or maintenance activity.

**False positive analysis**

* Routine maintenance or updates by authorized personnel can trigger deletion logs. Verify if the deletion aligns with scheduled maintenance activities and exclude these operations from alerts.
* Automated scripts or tools used for managing Azure resources might delete Event Hubs as part of their normal operation. Identify these scripts and whitelist their activity to prevent false positives.
* Test environments often involve frequent creation and deletion of resources, including Event Hubs. Exclude known test environments from monitoring to reduce noise.
* Changes in organizational policies or restructuring might lead to legitimate deletions. Ensure that such policy-driven deletions are documented and excluded from alerts.
* Misconfigured automation or deployment processes can inadvertently delete Event Hubs. Regularly review and update configurations to ensure they align with intended operations and exclude these from alerts if verified as non-threatening.

**Response and remediation**

* Immediately isolate the affected Azure Event Hub namespace to prevent further unauthorized deletions or modifications. This can be done by restricting access through Azure Role-Based Access Control (RBAC) and network security groups.
* Review and revoke any suspicious or unauthorized access permissions associated with the deleted Event Hub. Ensure that only authorized personnel have the necessary permissions to manage Event Hubs.
* Restore the deleted Event Hub from backups if available, or reconfigure it to resume normal operations. Verify the integrity and completeness of the restored data.
* Conduct a thorough audit of recent Azure activity logs to identify any other unauthorized actions or anomalies that may indicate further compromise.
* Escalate the incident to the security operations team for a detailed investigation into the root cause and to assess the potential impact on other Azure resources.
* Implement additional monitoring and alerting for Azure Event Hub operations to detect and respond to similar unauthorized activities promptly.
* Review and update security policies and access controls for Azure resources to prevent recurrence, ensuring adherence to the principle of least privilege.


## Setup [_setup_980]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5110]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
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

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



