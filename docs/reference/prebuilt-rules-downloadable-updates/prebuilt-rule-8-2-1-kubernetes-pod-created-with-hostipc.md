---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-kubernetes-pod-created-with-hostipc.html
---

# Kubernetes Pod Created With HostIPC [prebuilt-rule-8-2-1-kubernetes-pod-created-with-hostipc]

This rule detects an attempt to create or modify a pod using the host IPC namespace. This gives access to data used by any pod that also use the host�s IPC namespace. If any process on the host or any processes in a pod uses the host�s inter-process communication mechanisms (shared memory, semaphore arrays, message queues, etc.), an attacker can read/write to those same mechanisms. They may look for files in /dev/shm or use ipcs to check for any IPC facilities being used.

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
* [https://kubernetes.io/docs/concepts/security/pod-security-policy/#host-namespaces](https://kubernetes.io/docs/concepts/security/pod-security-policy/#host-namespaces)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution
* Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1964]



## Rule query [_rule_query_2249]

```js
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.hostIPC:true
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)



