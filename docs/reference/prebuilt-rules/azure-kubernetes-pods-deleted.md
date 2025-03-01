---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-kubernetes-pods-deleted.html
---

# Azure Kubernetes Pods Deleted [azure-kubernetes-pods-deleted]

Identifies the deletion of Azure Kubernetes Pods. Adversaries may delete a Kubernetes pod to disrupt the normal behavior of the environment.

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

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Asset Visibility
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_199]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Kubernetes Pods Deleted**

Azure Kubernetes Service (AKS) enables the deployment, management, and scaling of containerized applications using Kubernetes. Pods, the smallest deployable units in Kubernetes, can be targeted by adversaries to disrupt services or evade detection. Malicious actors might delete pods to cause downtime or hide their activities. The detection rule monitors Azure activity logs for successful pod deletion operations, alerting security teams to potential unauthorized actions that could impact the environment’s stability and security.

**Possible investigation steps**

* Review the Azure activity logs to confirm the details of the pod deletion event, focusing on the operation name "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and ensuring the event outcome is marked as "Success".
* Identify the user or service principal responsible for the deletion by examining the associated identity information in the activity logs.
* Check the timeline of events leading up to the pod deletion to identify any unusual or unauthorized access patterns or activities.
* Investigate the specific Kubernetes cluster and namespace where the pod deletion occurred to assess the potential impact on services and applications.
* Cross-reference the deleted pod’s details with recent changes or deployments in the environment to determine if the deletion was part of a legitimate maintenance or deployment activity.
* Consult with the relevant application or infrastructure teams to verify if the pod deletion was authorized and necessary, or if it indicates a potential security incident.

**False positive analysis**

* Routine maintenance or updates by authorized personnel can lead to legitimate pod deletions. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scaling operations might delete pods as part of normal scaling activities. Identify and exclude these operations by correlating with scaling events or using tags that indicate automated processes.
* Development and testing environments often experience frequent pod deletions as part of normal operations. Consider excluding these environments from alerts by using environment-specific identifiers or tags.
* Scheduled job completions may result in pod deletions once tasks are finished. Implement rules to recognize and exclude these scheduled operations by matching them with known job schedules or identifiers.

**Response and remediation**

* Immediately isolate the affected Kubernetes cluster to prevent further unauthorized actions. This can be done by restricting network access or applying stricter security group rules temporarily.
* Review the Azure activity logs to identify the source of the deletion request, including the user or service principal involved, and verify if the action was authorized.
* Recreate the deleted pods using the latest known good configuration to restore services and minimize downtime.
* Conduct a thorough security assessment of the affected cluster to identify any additional unauthorized changes or indicators of compromise.
* Implement stricter access controls and role-based access management to ensure only authorized personnel can delete pods in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional clusters or resources are affected.
* Enhance monitoring and alerting for similar activities by integrating with a Security Information and Event Management (SIEM) system to detect and respond to unauthorized pod deletions promptly.


## Setup [_setup_134]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_204]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and
event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)



