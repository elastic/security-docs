---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-virtual-private-network-connection-attempt.html
---

# Virtual Private Network Connection Attempt [prebuilt-rule-8-3-3-virtual-private-network-connection-attempt]

Identifies the execution of macOS built-in commands to connect to an existing Virtual Private Network (VPN). Adversaries may use VPN connections to laterally move and control remote systems on a network.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/vpn.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/vpn.rb)
* [https://www.unix.com/man-page/osx/8/networksetup/](https://www.unix.com/man-page/osx/8/networksetup/)
* [https://superuser.com/questions/358513/start-configured-vpn-from-command-line-osx](https://superuser.com/questions/358513/start-configured-vpn-from-command-line-osx)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Lateral Movement

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2970]



## Rule query [_rule_query_3440]

```js
process where event.type in ("start", "process_started") and
  (
    (process.name : "networksetup" and process.args : "-connectpppoeservice") or
    (process.name : "scutil" and process.args : "--nc" and process.args : "start") or
    (process.name : "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)



