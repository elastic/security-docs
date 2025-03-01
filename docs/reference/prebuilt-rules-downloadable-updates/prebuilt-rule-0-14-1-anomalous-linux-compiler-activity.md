---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-anomalous-linux-compiler-activity.html
---

# Anomalous Linux Compiler Activity [prebuilt-rule-0-14-1-anomalous-linux-compiler-activity]

Looks for compiler activity by a user context which does not normally run compilers. This can be the result of ad-hoc software changes or unauthorized software deployment. This can also be due to local privilege elevation via locally run exploits or malware activity.

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
* Linux
* Threat Detection
* ML

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

