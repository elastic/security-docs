---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-storage-bucket-permissions-modification.html
---

# GCP Storage Bucket Permissions Modification [prebuilt-rule-8-2-1-gcp-storage-bucket-permissions-modification]

Identifies when the Identity and Access Management (IAM) permissions are modified for a Google Cloud Platform (GCP) storage bucket. An adversary may modify the permissions on a storage bucket to weaken their target’s security controls or an administrator may inadvertently modify the permissions, which could lead to data exposure or loss.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/storage/docs/access-control/iam-permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1937]



## Rule query [_rule_query_2222]

```js
event.dataset:gcp.audit and event.action:"storage.setIamPermissions" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)



