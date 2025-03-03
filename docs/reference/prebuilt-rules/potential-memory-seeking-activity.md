---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-memory-seeking-activity.html
---

# Potential Memory Seeking Activity [potential-memory-seeking-activity]

Monitors for the execution of Unix utilities that may be leveraged as memory address seekers. Attackers may leverage built-in utilities to seek specific memory addresses, allowing for potential future manipulation/exploitation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_753]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and (
  (process.name == "tail" and process.args in ("-c", "--bytes")) or
  (process.name == "cmp" and process.args == "-i") or
  (process.name in ("hexdump", "xxd") and process.args == "-s") or
  (process.name == "dd" and process.args : ("skip*", "seek*"))
) and not (
  process.parent.args like ("/opt/error_monitor/error_monitor.sh", "printf*") or
  process.parent.name in ("acme.sh", "dracut", "leapp") or
  process.parent.executable like (
    "/bin/cagefs_enter", "/opt/nessus_agent/sbin/nessus-service", "/usr/libexec/platform-python*",
    "/usr/libexec/vdsm/vdsmd", "/usr/local/bin/docker-entrypoint.sh", "/usr/lib/module-init-tools/lsinitrd-quick"
  ) or
  process.parent.command_line like "sh*acme.sh*" or
  process.args like "/var/tmp/dracut*"
)
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



