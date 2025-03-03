---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-masquerading-space-after-filename.html
---

# Masquerading Space After Filename [prebuilt-rule-8-4-1-masquerading-space-after-filename]

This rules identifies a process created from an executable with a space appended to the end of the filename. This may indicate an attempt to masquerade a malicious file as benign to gain user execution. When a space is added to the end of certain files, the OS will execute the file according to it’s true filetype instead of it’s extension. Adversaries can hide a program’s true filetype by changing the extension of the file. They can then add a space to the end of the name so that the OS automatically executes the file when it’s double-clicked.

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

* [https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1036-masquerading](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1036-masquerading)

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2568]



## Rule query [_rule_query_2951]

```js
process where host.os.type:("linux","macos") and
  event.type == "start" and
  (process.executable regex~ """/[a-z0-9\s_\-\\./]+\s""") and not
  process.name in ("ls", "find", "grep", "xkbcomp")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Space after Filename
    * ID: T1036.006
    * Reference URL: [https://attack.mitre.org/techniques/T1036/006/](https://attack.mitre.org/techniques/T1036/006/)



