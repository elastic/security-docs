---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-kubernetes-rolebindings-created.html
---

# Azure Kubernetes Rolebindings Created [azure-kubernetes-rolebindings-created]

Identifies the creation of role binding or cluster role bindings. You can assign these roles to Kubernetes subjects (users, groups, or service accounts) with role bindings and cluster role bindings. An adversary who has permissions to create bindings and cluster-bindings in the cluster can create a binding to the cluster-admin ClusterRole or to other high privileges roles.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes)
* [https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_200]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Kubernetes Rolebindings Created**

Azure Kubernetes role bindings are crucial for managing access control within Kubernetes clusters, allowing specific permissions to be assigned to users, groups, or service accounts. Adversaries with the ability to create these bindings can escalate privileges by assigning themselves or others high-level roles, such as cluster-admin. The detection rule monitors Azure activity logs for successful creation events of role or cluster role bindings, signaling potential unauthorized privilege escalation attempts.

**Possible investigation steps**

* Review the Azure activity logs to identify the user or service account associated with the role binding creation event. Focus on the `event.dataset` and `azure.activitylogs.operation_name` fields to confirm the specific operation.
* Check the `event.outcome` field to ensure the operation was successful and not a failed attempt, which might indicate a misconfiguration or testing.
* Investigate the permissions and roles assigned to the identified user or service account to determine if they have legitimate reasons to create role bindings or cluster role bindings.
* Examine the context of the role binding creation, such as the time of the event and any related activities, to identify any unusual patterns or correlations with other suspicious activities.
* Verify if the role binding grants elevated privileges, such as cluster-admin, and assess the potential impact on the cluster’s security posture.
* Cross-reference the event with any recent changes in the cluster’s configuration or access policies to understand if the role binding creation aligns with authorized administrative actions.

**False positive analysis**

* Routine administrative tasks may trigger alerts when legitimate users create role bindings for operational purposes. To manage this, identify and whitelist specific user accounts or service accounts that regularly perform these tasks.
* Automated deployment tools or scripts that configure Kubernetes clusters might create role bindings as part of their normal operation. Exclude these tools by filtering out known service accounts or IP addresses associated with these automated processes.
* Scheduled maintenance or updates to the Kubernetes environment can result in multiple role binding creation events. Establish a maintenance window and suppress alerts during this period to avoid unnecessary noise.
* Development and testing environments often have frequent role binding changes. Consider creating separate monitoring rules with adjusted thresholds or risk scores for these environments to reduce false positives.
* Collaboration with the DevOps team can help identify expected role binding changes, allowing for preemptive exclusion of these events from triggering alerts.

**Response and remediation**

* Immediately revoke any newly created role bindings or cluster role bindings that are unauthorized or suspicious to prevent further privilege escalation.
* Isolate the affected Kubernetes cluster from the network to prevent potential lateral movement or further exploitation by the adversary.
* Conduct a thorough review of recent activity logs to identify any unauthorized access or changes made by the adversary, focusing on the time frame around the alert.
* Reset credentials and access tokens for any compromised accounts or service accounts involved in the unauthorized role binding creation.
* Escalate the incident to the security operations team for further investigation and to determine if additional clusters or resources are affected.
* Implement additional monitoring and alerting for any future role binding or cluster role binding creation events to ensure rapid detection and response.
* Review and tighten role-based access control (RBAC) policies to ensure that only necessary permissions are granted to users, groups, and service accounts, minimizing the risk of privilege escalation.


## Setup [_setup_135]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_205]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
	("MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE" or
	 "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE") and
event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



