---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-network-watcher-deletion.html
---

# Azure Network Watcher Deletion [azure-network-watcher-deletion]

Identifies the deletion of a Network Watcher in Azure. Network Watchers are used to monitor, diagnose, view metrics, and enable or disable logs for resources in an Azure virtual network. An adversary may delete a Network Watcher in an attempt to evade defenses.

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

* [https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview)

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

## Investigation guide [_investigation_guide_201]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Network Watcher Deletion**

Azure Network Watcher is a vital tool for monitoring and diagnosing network issues within Azure environments. It provides insights and logging capabilities crucial for maintaining network security. Adversaries may delete Network Watchers to disable these monitoring functions, thereby evading detection. The detection rule identifies such deletions by monitoring Azure activity logs for specific delete operations, flagging successful attempts as potential security threats.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by checking for the operation name "MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and ensuring the event outcome is marked as "Success" or "success".
* Identify the user or service principal responsible for the deletion by examining the associated user identity or service principal ID in the activity logs.
* Investigate the timeline of events leading up to the deletion by reviewing related activity logs for any unusual or unauthorized access patterns or changes in permissions.
* Assess the impact of the deletion by determining which resources were being monitored by the deleted Network Watcher and evaluating the potential security implications.
* Check for any other suspicious activities or alerts in the Azure environment that may indicate a broader attack or compromise, focusing on defense evasion tactics.

**False positive analysis**

* Routine maintenance activities by authorized personnel may trigger the deletion alert. Verify if the deletion aligns with scheduled maintenance and consider excluding these operations from alerts.
* Automated scripts or tools used for infrastructure management might delete Network Watchers as part of their normal operation. Identify these scripts and whitelist their activity to prevent false positives.
* Changes in network architecture or resource reallocation can lead to legitimate deletions. Review change management logs to confirm if the deletion was planned and adjust the detection rule to exclude these scenarios.
* Test environments often undergo frequent changes, including the deletion of Network Watchers. If these environments are known to generate false positives, consider creating exceptions for specific resource groups or subscriptions associated with testing.

**Response and remediation**

* Immediately isolate the affected Azure resources to prevent further unauthorized actions. This can be done by restricting network access or applying stricter security group rules.
* Review Azure activity logs to identify the user or service principal responsible for the deletion. Verify if the action was authorized and investigate any suspicious accounts.
* Restore the deleted Network Watcher by redeploying it in the affected regions to resume monitoring and logging capabilities.
* Conduct a security review of the affected Azure environment to identify any other potential misconfigurations or unauthorized changes.
* Implement stricter access controls and auditing for Azure resources, ensuring that only authorized personnel have the ability to delete critical monitoring tools like Network Watchers.
* Escalate the incident to the security operations team for further investigation and to determine if additional security measures are necessary.
* Enhance detection capabilities by ensuring that alerts for similar deletion activities are configured to notify the security team immediately.


## Setup [_setup_136]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_206]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
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



