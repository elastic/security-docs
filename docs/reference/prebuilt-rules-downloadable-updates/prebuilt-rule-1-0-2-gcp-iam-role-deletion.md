---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-gcp-iam-role-deletion.html
---

# GCP IAM Role Deletion [prebuilt-rule-1-0-2-gcp-iam-role-deletion]

Identifies an Identity and Access Management (IAM) role deletion in Google Cloud Platform (GCP). A role contains a set of permissions that allows you to perform specific actions on Google Cloud resources. An adversary may delete an IAM role to inhibit access to accounts utilized by legitimate users.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/iam/docs/understanding-roles](https://cloud.google.com/iam/docs/understanding-roles)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1434]

## Config

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1665]

```js
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



