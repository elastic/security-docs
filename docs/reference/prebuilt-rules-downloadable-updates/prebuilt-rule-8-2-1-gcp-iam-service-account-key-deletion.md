---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-iam-service-account-key-deletion.html
---

# GCP IAM Service Account Key Deletion [prebuilt-rule-8-2-1-gcp-iam-service-account-key-deletion]

Identifies the deletion of an Identity and Access Management (IAM) service account key in Google Cloud Platform (GCP). Each service account is associated with two sets of public/private RSA key pairs that are used to authenticate. If a key is deleted, the application will no longer be able to access Google Cloud resources using that key. A security best practice is to rotate your service account keys regularly.

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

* [https://cloud.google.com/iam/docs/service-accounts](https://cloud.google.com/iam/docs/service-accounts)
* [https://cloud.google.com/iam/docs/creating-managing-service-account-keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1947]



## Rule query [_rule_query_2232]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



