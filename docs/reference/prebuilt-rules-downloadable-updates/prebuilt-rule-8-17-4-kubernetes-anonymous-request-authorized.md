---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kubernetes-anonymous-request-authorized.html
---

# Kubernetes Anonymous Request Authorized [prebuilt-rule-8-17-4-kubernetes-anonymous-request-authorized]

This rule detects when an unauthenticated user request is authorized within the cluster. Attackers may attempt to use anonymous accounts to gain initial access to the cluster or to avoid attribution of their activities within the cluster. This rule excludes the /healthz, /livez and /readyz endpoints which are commonly accessed anonymously.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

**Tags**:

* Data Source: Kubernetes
* Tactic: Execution
* Tactic: Initial Access
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4196]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kubernetes Anonymous Request Authorized**

Kubernetes, a container orchestration platform, manages workloads and services. It uses authentication to control access. Adversaries might exploit anonymous access to perform unauthorized actions without leaving traces. The detection rule identifies unauthorized access by monitoring audit logs for anonymous requests that are allowed, excluding common health check endpoints, to flag potential misuse.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:kubernetes.audit_logs to identify the context and details of the anonymous request.
* Examine the kubernetes.audit.user.username field to confirm if the request was made by "system:anonymous" or "system:unauthenticated" and assess the potential risk associated with these accounts.
* Analyze the kubernetes.audit.requestURI to determine the target of the request and verify if it is outside the excluded endpoints (/healthz, /livez, /readyz), which could indicate suspicious activity.
* Investigate the source IP address and other network metadata associated with the request to identify the origin and assess if it aligns with known or expected traffic patterns.
* Check for any subsequent or related activities in the audit logs that might indicate further unauthorized actions or attempts to exploit the cluster.

**False positive analysis**

* Health check endpoints like /healthz, /livez, and /readyz are already excluded, but ensure any custom health check endpoints are also excluded to prevent false positives.
* Regularly scheduled maintenance tasks or automated scripts that use anonymous access for legitimate purposes should be identified and excluded from the rule to avoid unnecessary alerts.
* Some monitoring tools might use anonymous requests for gathering metrics; verify these tools and exclude their specific request patterns if they are known to be safe.
* Development environments might have different access patterns compared to production; consider creating separate rules or exceptions for non-production clusters to reduce noise.
* Review the audit logs to identify any recurring anonymous requests that are part of normal operations and adjust the rule to exclude these specific cases.

**Response and remediation**

* Immediately isolate the affected Kubernetes cluster to prevent further unauthorized access and potential lateral movement by the adversary.
* Revoke any anonymous access permissions that are not explicitly required for the operation of the cluster, ensuring that all access is authenticated and authorized.
* Conduct a thorough review of the audit logs to identify any unauthorized actions performed by anonymous users and assess the impact on the cluster.
* Reset credentials and access tokens for any accounts that may have been compromised or used in conjunction with the anonymous access.
* Implement network segmentation to limit the exposure of the Kubernetes API server to only trusted networks and users.
* Escalate the incident to the security operations team for further investigation and to determine if additional clusters or systems are affected.
* Enhance monitoring and alerting for unauthorized access attempts, focusing on detecting and responding to similar threats in the future.


## Setup [_setup_1058]

The Kubernetes Fleet integration with Audit Logs enabled or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5205]

```js
event.dataset:kubernetes.audit_logs
  and kubernetes.audit.annotations.authorization_k8s_io/decision:allow
  and kubernetes.audit.user.username:("system:anonymous" or "system:unauthenticated" or not *)
  and not kubernetes.audit.requestURI:(/healthz* or /livez* or /readyz*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Default Accounts
    * ID: T1078.001
    * Reference URL: [https://attack.mitre.org/techniques/T1078/001/](https://attack.mitre.org/techniques/T1078/001/)



