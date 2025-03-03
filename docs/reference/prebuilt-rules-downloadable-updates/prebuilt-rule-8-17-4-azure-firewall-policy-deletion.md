---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-firewall-policy-deletion.html
---

# Azure Firewall Policy Deletion [prebuilt-rule-8-17-4-azure-firewall-policy-deletion]

Identifies the deletion of a firewall policy in Azure. An adversary may delete a firewall policy in an attempt to evade defenses and/or to eliminate barriers to their objective.

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

* [https://docs.microsoft.com/en-us/azure/firewall-manager/policy-overview](https://docs.microsoft.com/en-us/azure/firewall-manager/policy-overview)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Network Security Monitoring
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4094]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Firewall Policy Deletion**

Azure Firewall policies are crucial for managing and enforcing network security rules across Azure environments. Adversaries may target these policies to disable security measures, facilitating unauthorized access or data exfiltration. The detection rule monitors Azure activity logs for successful deletion operations of firewall policies, signaling potential defense evasion attempts by identifying specific operation names and outcomes.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by filtering for the operation name "MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and ensuring the event outcome is "Success".
* Identify the user or service principal responsible for the deletion by examining the *caller* field in the activity logs.
* Check the timestamp of the deletion event to determine when the policy was deleted and correlate it with other security events or alerts around the same time.
* Investigate the context of the deletion by reviewing any related activities performed by the same user or service principal, such as modifications to other security settings or unusual login patterns.
* Assess the impact of the deletion by identifying which resources or networks were protected by the deleted firewall policy and evaluating the potential exposure or risk introduced by its removal.
* Contact the responsible user or team to verify if the deletion was authorized and part of a planned change or if it was unexpected and potentially malicious.

**False positive analysis**

* Routine maintenance or updates by authorized personnel can trigger the deletion event. Ensure that such activities are logged and verified by cross-referencing with change management records.
* Automated scripts or tools used for infrastructure management might delete and recreate firewall policies as part of their operation. Identify these scripts and exclude their activity from alerts by using specific identifiers or tags.
* Test environments often undergo frequent changes, including policy deletions. Consider excluding activity from known test environments by filtering based on resource group or subscription IDs.
* Scheduled policy updates or rotations might involve temporary deletions. Document these schedules and adjust monitoring rules to account for these expected changes.
* Ensure that any third-party integrations or services with permissions to modify firewall policies are accounted for, and their actions are reviewed and whitelisted if necessary.

**Response and remediation**

* Immediately isolate the affected Azure resources to prevent further unauthorized access or data exfiltration. This can be done by applying restrictive network security group (NSG) rules or using Azure Security Center to quarantine resources.
* Review Azure activity logs to identify the user or service principal responsible for the deletion. Verify if the action was authorized and investigate any suspicious accounts or credentials.
* Restore the deleted firewall policy from backups or recreate it using predefined templates to ensure that network security rules are reinstated promptly.
* Implement conditional access policies to enforce multi-factor authentication (MFA) for all users with permissions to modify or delete firewall policies, reducing the risk of unauthorized changes.
* Escalate the incident to the security operations team for further investigation and to determine if additional resources or systems have been compromised.
* Conduct a post-incident review to identify gaps in security controls and update incident response plans to address similar threats in the future.
* Enhance monitoring by configuring alerts for any future attempts to delete or modify critical security policies, ensuring rapid detection and response to potential threats.


## Setup [_setup_981]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5111]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
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



