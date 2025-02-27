---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-access-control-list-modification-via-setfacl.html
---

# Access Control List Modification via setfacl [prebuilt-rule-8-17-3-access-control-list-modification-via-setfacl]

This rule detects Linux Access Control List (ACL) modification via the setfacl command.

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

**References**:

* [https://www.uptycs.com/blog/threat-research-report-team/evasive-techniques-used-by-malicious-linux-shell-scripts](https://www.uptycs.com/blog/threat-research-report-team/evasive-techniques-used-by-malicious-linux-shell-scripts)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4863]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "setfacl" and not (
  process.command_line == "/bin/setfacl --restore=-" or
  process.args == "/var/log/journal/"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)

* Sub-technique:

    * Name: Linux and Mac File and Directory Permissions Modification
    * ID: T1222.002
    * Reference URL: [https://attack.mitre.org/techniques/T1222/002/](https://attack.mitre.org/techniques/T1222/002/)



