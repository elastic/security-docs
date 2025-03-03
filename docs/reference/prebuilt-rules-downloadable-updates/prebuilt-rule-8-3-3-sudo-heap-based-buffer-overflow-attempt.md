---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-sudo-heap-based-buffer-overflow-attempt.html
---

# Sudo Heap-Based Buffer Overflow Attempt [prebuilt-rule-8-3-3-sudo-heap-based-buffer-overflow-attempt]

Identifies the attempted use of a heap-based buffer overflow vulnerability for the Sudo binary in Unix-like systems (CVE-2021-3156). Successful exploitation allows an unprivileged user to escalate to the root user.

**Rule type**: threshold

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-3156](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-3156)
* [https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
* [https://www.bleepingcomputer.com/news/security/latest-macos-big-sur-also-has-sudo-root-privilege-escalation-flaw](https://www.bleepingcomputer.com/news/security/latest-macos-big-sur-also-has-sudo-root-privilege-escalation-flaw)
* [https://www.sudo.ws/alerts/unescape_overflow.html](https://www.sudo.ws/alerts/unescape_overflow.md)

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3299]

```js
event.category:process and event.type:start and
  process.name:(sudo or sudoedit) and
  process.args:(*\\ and ("-i" or "-s"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



