---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-kubernetes-suspicious-assignment-of-controller-service-account.html
---

# Kubernetes Suspicious Assignment of Controller Service Account [prebuilt-rule-8-4-2-kubernetes-suspicious-assignment-of-controller-service-account]

This rule detects a request to attach a controller service account to an existing or new pod running in the kube-system namespace. By default, controllers running as part of the API Server utilize admin-equivalent service accounts hosted in the kube-system namespace. Controller service accounts aren’t normally assigned to running pods and could indicate adversary behavior within the cluster. An attacker that can create or modify pods or pod controllers in the kube-system namespace, can assign one of these admin-equivalent service accounts to a pod and abuse their powerful token to escalate privileges and gain complete cluster control.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution
* Privilege Escalation

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3288]



## Rule query [_rule_query_3852]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb : "create"
  and kubernetes.audit.objectRef.resource : "pods"
  and kubernetes.audit.objectRef.namespace : "kube-system"
  and kubernetes.audit.requestObject.spec.serviceAccountName:*controller
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Default Accounts
    * ID: T1078.001
    * Reference URL: [https://attack.mitre.org/techniques/T1078/001/](https://attack.mitre.org/techniques/T1078/001/)



