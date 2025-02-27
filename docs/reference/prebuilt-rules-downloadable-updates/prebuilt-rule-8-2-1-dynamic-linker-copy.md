---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-dynamic-linker-copy.html
---

# Dynamic Linker Copy [prebuilt-rule-8-2-1-dynamic-linker-copy]

Detects the copying of the Linux dynamic loader binary and subsequent file creation for the purpose of creating a backup copy. This technique was seen recently being utilized by Linux malware prior to patching the dynamic loader in order to inject and preload a malicious shared object file. This activity should never occur and if it does then it should be considered highly suspicious or malicious.

**Rule type**: eql

**Rule indices**:

* logs-*

**Severity**: high

**Risk score**: 85

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/](https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence
* Orbit

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2321]

```js
sequence by process.entity_id with maxspan=1m
[process where event.type == "start" and process.name : ("cp", "rsync") and process.args : ("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload")]
[file where event.action == "creation" and file.extension == "so"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



