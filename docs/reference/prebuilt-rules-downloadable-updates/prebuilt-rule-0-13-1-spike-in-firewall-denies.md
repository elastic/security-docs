---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-1-spike-in-firewall-denies.html
---

# Spike in Firewall Denies [prebuilt-rule-0-13-1-spike-in-firewall-denies]

A machine learning job detected an unusually large spike in network traffic that was denied by network access control lists (ACLs) or firewall rules. Such a burst of denied traffic is usually caused by either 1) a mis-configured application or firewall or 2) suspicious or malicious activity. Unsuccessful attempts at network transit, in order to connect to command-and-control (C2), or engage in data exfiltration, may produce a burst of failed connections. This could also be due to unusually large amounts of reconnaissance or enumeration traffic. Denial-of-service attacks or traffic floods may also produce such a surge in traffic.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Elastic
* Network
* Threat Detection
* ML

**version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

