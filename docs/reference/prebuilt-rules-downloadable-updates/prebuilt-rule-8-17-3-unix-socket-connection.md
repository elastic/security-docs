---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-unix-socket-connection.html
---

# Unix Socket Connection [prebuilt-rule-8-17-3-unix-socket-connection]

This rule monitors for inter-process communication via Unix sockets. Adversaries may attempt to communicate with local Unix sockets to enumerate application details, find vulnerabilities/configuration mistakes and potentially escalate privileges or set up malicious communication channels via Unix sockets for inter-process communication to attempt to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
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
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4919]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 (
  (process.name in ("nc", "ncat", "netcat", "nc.openbsd") and
   process.args == "-U" and process.args : ("/usr/local/*", "/run/*", "/var/run/*")) or
  (process.name == "socat" and
   process.args == "-" and process.args : ("UNIX-CLIENT:/usr/local/*", "UNIX-CLIENT:/run/*", "UNIX-CLIENT:/var/run/*"))
) and
not process.args == "/var/run/libvirt/libvirt-sock"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Inter-Process Communication
    * ID: T1559
    * Reference URL: [https://attack.mitre.org/techniques/T1559/](https://attack.mitre.org/techniques/T1559/)



