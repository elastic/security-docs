---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-suspicious-which-enumeration.html
---

# Suspicious which Enumeration [prebuilt-rule-8-17-3-suspicious-which-enumeration]

This rule monitors for the usage of the which command with an unusual amount of process arguments. Attackers may leverage the which command to enumerate the system for useful installed utilities that may be used after compromising a system to escalate privileges or move latteraly across the network.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: SentinelOne

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4901]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start") and
  process.name == "which" and process.args_count >= 10 and not (
    process.parent.name == "jem" or
    process.parent.executable like ("/vz/root/*", "/var/lib/docker/*") or
    process.args == "--tty-only"
  )

/* potential tuning if rule would turn out to be noisy
and process.args in ("nmap", "nc", "ncat", "netcat", nc.traditional", "gcc", "g++", "socat") and
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
*/
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



