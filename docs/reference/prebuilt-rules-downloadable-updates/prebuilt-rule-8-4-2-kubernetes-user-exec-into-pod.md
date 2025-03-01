---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-kubernetes-user-exec-into-pod.html
---

# Kubernetes User Exec into Pod [prebuilt-rule-8-4-2-kubernetes-user-exec-into-pod]

This rule detects a user attempt to establish a shell session into a pod using the *exec* command. Using the *exec* command in a pod allows a user to establish a temporary shell session and execute any process/commands in the pod. An adversary may call bash to gain a persistent interactive shell which will allow access to any data the pod has permissions to, including secrets.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
* [https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/](https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution

**Version**: 201

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3279]



## Rule query [_rule_query_3843]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb:"create"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.objectRef.subresource:"exec"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Container Administration Command
    * ID: T1609
    * Reference URL: [https://attack.mitre.org/techniques/T1609/](https://attack.mitre.org/techniques/T1609/)



