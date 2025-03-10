---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-ipv4-ipv6-forwarding-activity.html
---

# IPv4/IPv6 Forwarding Activity [prebuilt-rule-8-17-3-ipv4-ipv6-forwarding-activity]

This rule monitors for the execution of commands that enable IPv4 and IPv6 forwarding on Linux systems. Enabling IP forwarding can be used to route network traffic between different network interfaces, potentially allowing attackers to pivot between networks, exfiltrate data, or establish command and control channels.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Command and Control
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4852]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "exec_event") and
process.parent.executable != null and process.command_line like (
  "*net.ipv4.ip_forward*", "*/proc/sys/net/ipv4/ip_forward*", "*net.ipv6.conf.all.forwarding*",
  "*/proc/sys/net/ipv6/conf/all/forwarding*"
) and (
  (process.name == "sysctl" and process.args like ("*-w*", "*--write*", "*=*")) or
  (
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and
    process.command_line like "*echo *"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



