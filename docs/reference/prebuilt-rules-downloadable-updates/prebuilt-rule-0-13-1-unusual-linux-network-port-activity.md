---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-1-unusual-linux-network-port-activity.html
---

# Unusual Linux Network Port Activity [prebuilt-rule-0-13-1-unusual-linux-network-port-activity]

Identifies unusual destination port activity that can indicate command-and-control, persistence mechanism, or data exfiltration activity. Rarely used destination port activity is generally unusual in Linux fleets, and can indicate unauthorized access or threat actor activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* ML

**version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

