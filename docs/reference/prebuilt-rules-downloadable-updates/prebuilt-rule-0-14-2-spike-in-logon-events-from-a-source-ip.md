---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-spike-in-logon-events-from-a-source-ip.html
---

# Spike in Logon Events from a Source IP [prebuilt-rule-0-14-2-spike-in-logon-events-from-a-source-ip]

A machine learning job found an unusually large spike in successful authentication events from a particular source IP address. This can be due to password spraying, user enumeration or brute force activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Authentication
* Threat Detection
* ML

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

