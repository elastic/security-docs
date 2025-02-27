---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-suspicious-memory-grep-activity.html
---

# Suspicious Memory grep Activity [prebuilt-rule-8-17-3-suspicious-memory-grep-activity]

Monitors for grep activity related to memory mapping. The /proc/*/maps file in Linux provides a memory map for a specific process, detailing the memory segments, permissions, and what files are mapped to these segments. Attackers may read a process’s memory map to identify memory addresses for code injection or process hijacking.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4900]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name in ("grep", "egrep", "fgrep", "rgrep") and process.args in ("[stack]", "[vdso]", "[heap]")
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



