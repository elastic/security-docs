---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-windows-user-calling-the-metadata-service.html
---

# Unusual Windows User Calling the Metadata Service [prebuilt-rule-8-1-1-unusual-windows-user-calling-the-metadata-service]

Looks for anomalous access to the cloud platform metadata service by an unusual user. The metadata service may be targeted in order to harvest credentials or user data scripts containing secrets.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

