---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-forwarded-google-workspace-security-alert.html
---

# Forwarded Google Workspace Security Alert [prebuilt-rule-8-17-4-forwarded-google-workspace-security-alert]

Identifies the occurrence of a security alert from the Google Workspace alerts center. Google Workspace’s security alert center provides an overview of actionable alerts that may be affecting an organization’s domain. An alert is a warning of a potential security issue that Google has detected.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://workspace.google.com/products/admin/alert-center/](https://workspace.google.com/products/admin/alert-center/)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
* [https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)

**Tags**:

* Domain: Cloud
* Data Source: Google Workspace
* Use Case: Log Auditing
* Use Case: Threat Detection
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4191]

**Triage and analysis**

This is a promotion rule for Google Workspace security events, which are alertable events per the vendor. Consult vendor documentation on interpreting specific events.


## Setup [_setup_1053]



## Rule query [_rule_query_5200]

```js
event.dataset: google_workspace.alert
```


