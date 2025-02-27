---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-service-account-key-creation.html
---

# GCP Service Account Key Creation [prebuilt-rule-8-2-1-gcp-service-account-key-creation]

Identifies when a new key is created for a service account in Google Cloud Platform (GCP). A service account is a special type of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as G Suite or Cloud Identity users through domain-wide delegation. If private keys are not tracked and managed properly, they can present a security risk. An adversary may create a new key for a service account in order to attempt to abuse the permissions assigned to that account and evade detection.

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

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1948]



## Rule query [_rule_query_2233]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
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



