---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-rare-user-logon.html
---

# Rare User Logon [prebuilt-rule-0-14-2-rare-user-logon]

A machine learning job found an unusual user name in the authentication logs. An unusual user name is one way of detecting credentialed access by means of a new or dormant user account. An inactive user account (because the user has left the organization) that becomes active may be due to credentialed access using a compromised account password. Threat actors will sometimes also create new users as a means of persisting in a compromised web application.

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

