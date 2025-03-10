---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kubernetes-user-exec-into-pod.html
---

# Kubernetes User Exec into Pod [kubernetes-user-exec-into-pod]

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

* Data Source: Kubernetes
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_466]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kubernetes User Exec into Pod**

Kubernetes allows users to execute commands within a pod using the *exec* command, facilitating temporary shell sessions for legitimate management tasks. However, adversaries can exploit this to gain unauthorized access, potentially exposing sensitive data. The detection rule identifies such misuse by monitoring audit logs for specific patterns, such as allowed *exec* actions on pods, indicating possible malicious activity.

**Possible investigation steps**

* Review the Kubernetes audit logs to identify the user who executed the *exec* command by examining the event.dataset field for "kubernetes.audit_logs".
* Check the kubernetes.audit.annotations.authorization_k8s_io/decision field to confirm that the action was allowed and determine if the user had legitimate access.
* Investigate the kubernetes.audit.objectRef.resource and kubernetes.audit.objectRef.subresource fields to verify that the action involved a pod and the *exec* subresource.
* Analyze the context of the pod involved, including its purpose and the data it has access to, to assess the potential impact of the unauthorized access.
* Correlate the event with other logs or alerts to identify any suspicious patterns or repeated unauthorized access attempts by the same user or IP address.
* Review the user’s activity history to determine if there are other instances of unusual or unauthorized access attempts within the Kubernetes environment.

**False positive analysis**

* Routine administrative tasks by DevOps teams can trigger the rule when they use *exec* for legitimate management purposes. To handle this, create exceptions for specific user accounts or roles that are known to perform these tasks regularly.
* Automated scripts or tools that use *exec* for monitoring or maintenance can also cause false positives. Identify these scripts and whitelist their associated service accounts or IP addresses.
* Scheduled jobs or cron tasks that require *exec* to perform updates or checks within pods may be flagged. Exclude these by setting up time-based exceptions for known maintenance windows.
* Development environments where frequent testing and debugging occur using *exec* can lead to alerts. Implement environment-specific exclusions to reduce noise from non-production clusters.

**Response and remediation**

* Immediately isolate the affected pod to prevent further unauthorized access or data exposure. This can be done by applying network policies or temporarily scaling down the pod.
* Review the audit logs to identify the user or service account responsible for the *exec* command and assess whether the access was legitimate or unauthorized.
* Revoke or adjust permissions for the identified user or service account to prevent further unauthorized *exec* actions. Ensure that only necessary permissions are granted following the principle of least privilege.
* Conduct a thorough investigation of the pod’s environment to identify any potential data exposure or tampering. Check for unauthorized changes to configurations, secrets, or data within the pod.
* If unauthorized access is confirmed, rotate any exposed secrets or credentials that the pod had access to, and update any affected systems or services.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems or pods have been compromised.
* Enhance monitoring and alerting for similar *exec* actions in the future by ensuring that audit logs are continuously reviewed and that alerts are configured to notify the security team of any suspicious activity.


## Setup [_setup_301]

The Kubernetes Fleet integration with Audit Logs enabled or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_501]

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



