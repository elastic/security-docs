---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-privilege-escalation-via-rogue-named-pipe-impersonation.html
---

# Privilege Escalation via Rogue Named Pipe Impersonation [prebuilt-rule-0-14-3-privilege-escalation-via-rogue-named-pipe-impersonation]

Identifies a privilege escalation attempt via rogue named pipe impersonation. An adversary may abuse this technique by masquerading as a known named pipe and manipulating a privileged process to connect to it.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
* [https://twitter.com/SBousseaden/status/1429530155291193354](https://twitter.com/SBousseaden/status/1429530155291193354)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1342]

## Config

Named Pipe Creation Events need to be enabled within the Sysmon configuration by including the following settings:
`condition equal "contains" and keyword equal "pipe"`

## Rule query [_rule_query_1519]

```js
file where event.action : "Pipe Created*" and
 /* normal sysmon named pipe creation events truncate the pipe keyword */
  file.name : "\\*\\Pipe\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



