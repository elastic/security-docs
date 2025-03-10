---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/process-discovery-via-built-in-applications.html
---

# Process Discovery via Built-In Applications [process-discovery-via-built-in-applications]

Identifies the use of built-in tools attackers can use to discover running processes on an endpoint.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_889]

```js
process where event.type == "start" and event.action in ("exec", "exec_event") and process.name in (
  "ps", "pstree", "htop", "pgrep"
) and
not process.parent.name in ("amazon-ssm-agent", "snap")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)

* Sub-technique:

    * Name: Security Software Discovery
    * ID: T1518.001
    * Reference URL: [https://attack.mitre.org/techniques/T1518/001/](https://attack.mitre.org/techniques/T1518/001/)



