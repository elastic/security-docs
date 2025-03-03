---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-kubernetes-anonymous-request-authorized.html
---

# Kubernetes Anonymous Request Authorized [prebuilt-rule-8-4-1-kubernetes-anonymous-request-authorized]

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

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution
* Initial Access
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2571]



## Rule query [_rule_query_2955]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and (kubernetes.audit.user.username:("system:anonymous" or "system:unauthenticated") or not kubernetes.audit.user.username:*)
  and not kubernetes.audit.objectRef.resource:("healthz" or "livez" or "readyz")
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



