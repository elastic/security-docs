---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-virtual-network-device-modified-or-deleted.html
---

# Azure Virtual Network Device Modified or Deleted [azure-virtual-network-device-modified-or-deleted]

Identifies when a virtual network device is modified or deleted. This can be a network virtual appliance, virtual hub, or virtual router.

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

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Network Security Monitoring
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_207]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Virtual Network Device Modified or Deleted**

Azure virtual network devices, such as network interfaces, virtual hubs, and routers, are crucial for managing network traffic and connectivity in cloud environments. Adversaries may target these devices to disrupt services or reroute traffic for malicious purposes. The detection rule monitors specific Azure activity logs for operations indicating modifications or deletions of these devices, helping identify potential unauthorized changes that could signify an attack.

**Possible investigation steps**

* Review the Azure activity logs to identify the specific operation that triggered the alert, focusing on the operation_name field to determine whether it was a WRITE or DELETE action.
* Check the event.outcome field to confirm the success of the operation, ensuring that the modification or deletion was completed.
* Investigate the user or service principal responsible for the action by examining the identity information in the activity logs to determine if the change was authorized.
* Assess the impact of the modification or deletion by identifying the affected virtual network device, such as a network interface, virtual hub, or virtual router, and evaluate its role in the network architecture.
* Cross-reference the time of the alert with any other suspicious activities or alerts in the environment to identify potential patterns or coordinated actions.
* Consult with relevant stakeholders or system owners to verify if the change was planned or expected, and gather additional context if necessary.

**False positive analysis**

* Routine maintenance activities by network administrators can trigger alerts when they modify or delete virtual network devices. To manage this, create exceptions for known maintenance windows or specific administrator accounts.
* Automated scripts or tools used for network management might perform frequent updates or deletions, leading to false positives. Identify these scripts and exclude their operations from triggering alerts by using specific identifiers or tags.
* Changes made by authorized third-party services or integrations that manage network configurations can also result in false positives. Review and whitelist these services to prevent unnecessary alerts.
* Regular updates or deployments in a development or testing environment may cause alerts. Consider excluding these environments from monitoring or adjusting the rule to focus on production environments only.
* Temporary changes for troubleshooting or testing purposes might be flagged. Document these activities and use temporary exceptions to avoid false positives during these periods.

**Response and remediation**

* Immediately isolate the affected virtual network device to prevent further unauthorized access or changes. This can be done by disabling the network interface or applying restrictive network security group rules.
* Review the Azure activity logs to identify the source of the modification or deletion. Correlate this with user activity logs to determine if the action was performed by an authorized user or a compromised account.
* If a compromised account is suspected, reset the credentials for the affected account and any other accounts that may have been exposed. Implement multi-factor authentication if not already in place.
* Restore the modified or deleted virtual network device from a known good backup or configuration snapshot to ensure continuity of services.
* Conduct a thorough security assessment of the affected Azure environment to identify any additional unauthorized changes or indicators of compromise.
* Escalate the incident to the security operations team for further investigation and to determine if additional containment measures are necessary.
* Implement enhanced monitoring and alerting for similar activities in the future, ensuring that any modifications or deletions of virtual network devices are promptly detected and reviewed.


## Setup [_setup_142]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_212]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:("MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE" or "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION" or "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE" or
"MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE" or "MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE" or
"MICROSOFT.NETWORK/VIRTUALHUBS/DELETE" or "MICROSOFT.NETWORK/VIRTUALHUBS/WRITE" or
"MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE" or "MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE") and
event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)



