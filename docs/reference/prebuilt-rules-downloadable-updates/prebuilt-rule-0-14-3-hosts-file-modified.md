---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-hosts-file-modified.html
---

# Hosts File Modified [prebuilt-rule-0-14-3-hosts-file-modified]

The hosts file on endpoints is used to control manual IP address to hostname resolutions. The hosts file is the first point of lookup for DNS hostname resolution so if adversaries can modify the endpoint hosts file, they can route traffic to malicious infrastructure. This rule detects modifications to the hosts file on Microsoft Windows, Linux (Ubuntu or RHEL) and macOS systems.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/beats/docs/reference/ingestion-tools/beats-auditbeat/auditbeat-reference-yml.md](beats://reference/auditbeat/auditbeat-reference-yml.md)

**Tags**:

* Elastic
* Host
* Linux
* Windows
* macOS
* Threat Detection
* Impact

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1343]

## Config

For Windows systems using Auditbeat, this rule requires adding `C:/Windows/System32/drivers/etc` as an additional path in the 'file_integrity' module of auditbeat.yml.

## Rule query [_rule_query_1521]

```js
any where

  /* file events for creation; file change events are not captured by some of the included sources for linux and so may
     miss this, which is the purpose of the process + command line args logic below */
  (
   event.category == "file" and event.type in ("change", "creation") and
     file.path : ("/private/etc/hosts", "/etc/hosts", "?:\\Windows\\System32\\drivers\\etc\\hosts")
  )
  or

  /* process events for change targeting linux only */
  (
   event.category == "process" and event.type in ("start") and
     process.name in ("nano", "vim", "vi", "emacs", "echo", "sed") and
     process.args : ("/etc/hosts")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Manipulation
    * ID: T1565
    * Reference URL: [https://attack.mitre.org/techniques/T1565/](https://attack.mitre.org/techniques/T1565/)

* Sub-technique:

    * Name: Stored Data Manipulation
    * ID: T1565.001
    * Reference URL: [https://attack.mitre.org/techniques/T1565/001/](https://attack.mitre.org/techniques/T1565/001/)



