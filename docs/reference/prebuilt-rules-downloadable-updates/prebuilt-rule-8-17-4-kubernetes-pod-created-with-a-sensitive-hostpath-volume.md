---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kubernetes-pod-created-with-a-sensitive-hostpath-volume.html
---

# Kubernetes Pod created with a Sensitive hostPath Volume [prebuilt-rule-8-17-4-kubernetes-pod-created-with-a-sensitive-hostpath-volume]

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

* Data Source: Kubernetes
* Tactic: Execution
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4202]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kubernetes Pod created with a Sensitive hostPath Volume**

Kubernetes allows containers to access host filesystems via hostPath volumes, which can be crucial for certain applications. However, if a container is compromised, adversaries can exploit these mounts to access sensitive host data or escalate privileges. The detection rule identifies when pods are created or modified with hostPath volumes pointing to critical directories, signaling potential misuse or security risks.

**Possible investigation steps**

* Review the Kubernetes audit logs to identify the specific pod creation or modification event that triggered the alert, focusing on the event.dataset field with the value "kubernetes.audit_logs".
* Examine the kubernetes.audit.requestObject.spec.volumes.hostPath.path field to determine which sensitive hostPath was mounted and assess the potential risk associated with that specific path.
* Check the kubernetes.audit.annotations.authorization_k8s_io/decision field to confirm that the action was allowed, and verify the legitimacy of the authorization decision.
* Investigate the kubernetes.audit.requestObject.spec.containers.image field to identify the container image used, ensuring it is not a known or suspected malicious image, and cross-reference with any known vulnerabilities or security advisories.
* Analyze the context of the pod creation or modification by reviewing the kubernetes.audit.verb field to understand whether the action was a create, update, or patch operation, and correlate this with recent changes or deployments in the environment.
* Assess the potential impact on the cluster by identifying other pods or services that might be affected by the compromised pod, especially those with elevated privileges or access to sensitive data.

**False positive analysis**

* Development environments often use hostPath volumes for testing purposes, which can trigger this rule. To manage this, create exceptions for specific namespaces or labels associated with development workloads.
* Monitoring tools or agents may require access to certain host paths for legitimate reasons. Identify these tools and exclude their specific container images from the rule, similar to the exclusion of the elastic-agent image.
* Backup or logging applications might need access to host directories to perform their functions. Review these applications and consider excluding their specific hostPath configurations if they are deemed non-threatening.
* Some system maintenance tasks might temporarily use hostPath volumes. Document these tasks and schedule them during known maintenance windows, then create temporary exceptions during these periods.
* Custom scripts or automation tools that interact with Kubernetes may inadvertently trigger this rule. Audit these scripts and tools, and if they are safe, exclude their specific actions or paths from the rule.

**Response and remediation**

* Immediately isolate the affected pod to prevent further access to sensitive host data. This can be done by cordoning the node or deleting the pod if necessary.
* Review and revoke any credentials or tokens that may have been exposed through the compromised pod to prevent unauthorized access to other resources.
* Conduct a thorough analysis of the container image and application code to identify any vulnerabilities or malicious code that may have led to the compromise.
* Patch or update the container image and application code to address any identified vulnerabilities, and redeploy the application with the updated image.
* Implement network policies to restrict pod-to-pod and pod-to-node communication, limiting the potential impact of a compromised pod.
* Enhance monitoring and logging for Kubernetes audit logs to ensure timely detection of similar threats in the future, focusing on unauthorized access attempts and privilege escalation activities.
* Escalate the incident to the security operations team for further investigation and to assess the need for additional security measures or incident response actions.


## Setup [_setup_1064]

The Kubernetes Fleet integration with Audit Logs enabled or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5211]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.volumes.hostPath.path:
  ("/" or
  "/proc" or
  "/root" or
  "/var" or
  "/var/run" or
  "/var/run/docker.sock" or
  "/var/run/crio/crio.sock" or
  "/var/run/cri-dockerd.sock" or
  "/var/lib/kubelet" or
  "/var/lib/kubelet/pki" or
  "/var/lib/docker/overlay2" or
  "/etc" or
  "/etc/kubernetes" or
  "/etc/kubernetes/manifests" or
  "/etc/kubernetes/pki" or
  "/home/admin")
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Deploy Container
    * ID: T1610
    * Reference URL: [https://attack.mitre.org/techniques/T1610/](https://attack.mitre.org/techniques/T1610/)



