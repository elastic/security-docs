---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-kubernetes-denied-service-account-request.html
---

# Kubernetes Denied Service Account Request [prebuilt-rule-8-4-1-kubernetes-denied-service-account-request]

This rule detects when a service account makes an unauthorized request for resources from the API server. Service accounts follow a very predictable pattern of behavior. A service account should never send an unauthorized request to the API server. This behavior is likely an indicator of compromise or of a problem within the cluster. An adversary may have gained access to credentials/tokens and this could be an attempt to access or create resources to facilitate further movement or execution within the cluster.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections](https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections)
* [https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Discovery

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2570]



## Rule query [_rule_query_2954]

```js
event.dataset: "kubernetes.audit_logs"
  and kubernetes.audit.user.username: system\:serviceaccount\:*
  and kubernetes.audit.annotations.authorization_k8s_io/decision: "forbid"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Container and Resource Discovery
    * ID: T1613
    * Reference URL: [https://attack.mitre.org/techniques/T1613/](https://attack.mitre.org/techniques/T1613/)



