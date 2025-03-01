---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potentially-suspicious-process-started-via-tmux-or-screen.html
---

# Potentially Suspicious Process Started via tmux or screen [prebuilt-rule-8-17-3-potentially-suspicious-process-started-via-tmux-or-screen]

This rule monitors for the execution of suspicious commands via screen and tmux. When launching a command and detaching directly, the commands will be executed in the background via its parent process. Attackers may leverage screen or tmux to execute commands while attempting to evade detection.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4889]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.parent.name in ("screen", "tmux") and process.name like (
    "nmap", "nc", "ncat", "netcat", "socat", "nc.openbsd", "ngrok", "ping", "java", "php*", "perl", "ruby", "lua*",
    "openssl", "telnet", "wget", "curl", "id"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



