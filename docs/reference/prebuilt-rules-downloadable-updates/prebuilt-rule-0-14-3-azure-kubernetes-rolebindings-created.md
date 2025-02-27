---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-azure-kubernetes-rolebindings-created.html
---

# Azure Kubernetes Rolebindings Created [prebuilt-rule-0-14-3-azure-kubernetes-rolebindings-created]

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

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 1

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1336]

## Config

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1499]

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



