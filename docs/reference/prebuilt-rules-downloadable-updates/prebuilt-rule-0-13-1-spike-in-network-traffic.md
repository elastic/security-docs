---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-1-spike-in-network-traffic.html
---

# Spike in Network Traffic [prebuilt-rule-0-13-1-spike-in-network-traffic]

A machine learning job detected an unusually large spike in network traffic. Such a burst of traffic, if not caused by a surge in business activity, can be due to suspicious or malicious activity. Large-scale data exfiltration may produce a burst of network traffic; this could also be due to unusually large amounts of reconnaissance or enumeration traffic. Denial-of-service attacks or traffic floods may also produce such a surge in traffic.

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
* Network
* Threat Detection
* ML

**version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

