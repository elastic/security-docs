---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-kubernetes-pod-created-with-a-sensitive-hostpath-volume.html
---

# Kubernetes Pod created with a Sensitive hostPath Volume [prebuilt-rule-8-2-1-kubernetes-pod-created-with-a-sensitive-hostpath-volume]

This rule detects when a pod is created with a sensitive volume of type hostPath. A hostPath volume type mounts a sensitive file or folder from the node to the container. If the container gets compromised, the attacker can use this mount for gaining access to the node. There are many ways a container with unrestricted access to the host filesystem can escalate privileges, including reading data from other containers, and accessing tokens of more privileged pods.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.appsecco.com/kubernetes-namespace-breakout-using-insecure-host-path-volume-part-1-b382f2a6e216](https://blog.appsecco.com/kubernetes-namespace-breakout-using-insecure-host-path-volume-part-1-b382f2a6e216)
* [https://kubernetes.io/docs/concepts/storage/volumes/#hostpath](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)

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

## Investigation guide [_investigation_guide_1967]



## Rule query [_rule_query_2252]

```js
kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.volumes.hostPath.path:("/" or "/proc" or "/root" or "/var" or "/var/run/docker.sock" or "/var/run/crio/crio.sock" or "/var/run/cri-dockerd.sock" or "/var/lib/kubelet" or "/var/lib/kubelet/pki" or "/var/lib/docker/overlay2" or "/etc" or "/etc/kubernetes" or "/etc/kubernetes/manifests" or "/home/admin")
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



