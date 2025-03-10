---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-kubernetes-rolebindings-created-or-patched.html
---

# GCP Kubernetes Rolebindings Created or Patched [prebuilt-rule-8-2-1-gcp-kubernetes-rolebindings-created-or-patched]

Identifies the creation or patching of potentially malicious role bindings. Users can use role bindings and cluster role bindings to assign roles to Kubernetes subjects (users, groups, or service accounts).

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging)
* [https://unofficial-kubernetes.readthedocs.io/en/latest/admin/authorization/rbac/](https://unofficial-kubernetes.readthedocs.io/en/latest/admin/authorization/rbac/)
* [https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control](https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 4

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1950]



## Rule query [_rule_query_2235]

```js
event.dataset:(googlecloud.audit or gcp.audit) and event.action:(io.k8s.authorization.rbac.v*.clusterrolebindings.create or
io.k8s.authorization.rbac.v*.rolebindings.create or io.k8s.authorization.rbac.v*.clusterrolebindings.patch or
io.k8s.authorization.rbac.v*.rolebindings.patch) and event.outcome:success and
not gcp.audit.authentication_info.principal_email:"system:addon-manager"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



