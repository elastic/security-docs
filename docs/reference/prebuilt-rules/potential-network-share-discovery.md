---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-network-share-discovery.html
---

# Potential Network Share Discovery [potential-network-share-discovery]

Adversaries may look for folders and drives shared on remote systems to identify sources of information to gather as a precursor for collection and identify potential systems of interest for Lateral Movement.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-system.security*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Collection
* Rule Type: BBR
* Data Source: System

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_759]

```js
sequence by user.name, source.port, source.ip with maxspan=15s
 [file where event.action == "network-share-object-access-checked" and
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
 [file where event.action == "network-share-object-access-checked" and
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Network Shared Drive
    * ID: T1039
    * Reference URL: [https://attack.mitre.org/techniques/T1039/](https://attack.mitre.org/techniques/T1039/)



