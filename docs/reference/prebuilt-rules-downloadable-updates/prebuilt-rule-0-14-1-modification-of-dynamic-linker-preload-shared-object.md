---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-modification-of-dynamic-linker-preload-shared-object.html
---

# Modification of Dynamic Linker Preload Shared Object [prebuilt-rule-0-14-1-modification-of-dynamic-linker-preload-shared-object]

Identifies modification of the dynamic linker preload shared object (ld.so.preload). Adversaries may execute malicious payloads by hijacking the dynamic linker used to load libraries.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang](https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1350]

```js
event.category:file and not event.type:deletion and file.path:/etc/ld.so.preload
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



