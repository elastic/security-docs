---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kubernetes-pod-created-with-hostnetwork.html
---

# Kubernetes Pod Created With HostNetwork [kubernetes-pod-created-with-hostnetwork]

This rules detects an attempt to create or modify a pod attached to the host network. HostNetwork allows a pod to use the node network namespace. Doing so gives the pod access to any service running on localhost of the host. An attacker could use this access to snoop on network activity of other pods on the same node or bypass restrictive network policies applied to its given namespace.

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

* Data Source: Kubernetes
* Tactic: Execution
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_460]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kubernetes Pod Created With HostNetwork**

Kubernetes allows pods to connect to the host’s network namespace using HostNetwork, granting them direct access to the node’s network interfaces. This capability can be exploited by attackers to monitor or intercept network traffic, potentially bypassing network policies. The detection rule identifies suspicious pod creation or modification events with HostNetwork enabled, excluding known benign images, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the Kubernetes audit logs to identify the source of the pod creation or modification event, focusing on the user or service account associated with the action.
* Examine the pod’s configuration details, especially the containers' images, to determine if any unauthorized or suspicious images are being used, excluding known benign images like "docker.elastic.co/beats/elastic-agent:8.4.0".
* Investigate the network activity of the node where the pod is running to identify any unusual traffic patterns or potential data exfiltration attempts.
* Check the Kubernetes RBAC (Role-Based Access Control) settings to ensure that the user or service account has appropriate permissions and is not overly privileged.
* Assess the necessity of using HostNetwork for the pod in question and determine if it can be reconfigured to operate without this setting to reduce potential security risks.

**False positive analysis**

* Pods used for monitoring or logging may require HostNetwork access to gather network data across nodes. Users can exclude these by adding their specific container images to the exception list in the detection rule.
* Certain system-level services or infrastructure components might need HostNetwork for legitimate reasons, such as network plugins or ingress controllers. Identify these services and update the rule to exclude their specific images or namespaces.
* Development or testing environments might frequently create pods with HostNetwork for debugging purposes. Consider creating a separate rule or environment-specific exceptions to avoid alert fatigue in these scenarios.
* Pods that are part of a known and trusted deployment process, which require HostNetwork for valid operational reasons, should be documented and excluded from the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected pod by cordoning the node to prevent new pods from being scheduled and draining existing pods to other nodes, except the suspicious one.
* Terminate the suspicious pod to stop any potential malicious activity and prevent further network access.
* Review and revoke any unnecessary permissions or roles associated with the service account used by the pod to limit privilege escalation opportunities.
* Conduct a thorough audit of network policies to ensure they are correctly configured to prevent unauthorized access to the host network.
* Escalate the incident to the security operations team for further investigation and to determine if any data was accessed or exfiltrated.
* Implement additional monitoring and alerting for any future pod creations with HostNetwork enabled to quickly detect similar threats.
* Review and update Kubernetes RBAC policies to enforce the principle of least privilege, ensuring only trusted entities can create pods with HostNetwork enabled.


## Setup [_setup_295]

The Kubernetes Fleet integration with Audit Logs enabled or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_495]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.hostNetwork:true
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



