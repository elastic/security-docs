---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-attempt-to-remove-file-quarantine-attribute.html
---

# Attempt to Remove File Quarantine Attribute [prebuilt-rule-8-2-1-attempt-to-remove-file-quarantine-attribute]

Identifies a potential Gatekeeper bypass. In macOS, when applications or programs are downloaded from the internet, there is a quarantine flag set on the file. This attribute is read by Apple’s Gatekeeper defense program at execution time. An adversary may disable this attribute to evade defenses.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html](https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.md)
* [https://ss64.com/osx/xattr.html](https://ss64.com/osx/xattr.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2040]



## Rule query [_rule_query_2330]

```js
process where event.type in ("start", "process_started") and
  process.name : "xattr" and
  (
    (process.args : "com.apple.quarantine" and process.args : ("-d", "-w")) or
    (process.args : "-c") or
    (process.command_line : ("/bin/bash -c xattr -c *", "/bin/zsh -c xattr -c *", "/bin/sh -c xattr -c *"))
  ) and not process.args_count > 12
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



