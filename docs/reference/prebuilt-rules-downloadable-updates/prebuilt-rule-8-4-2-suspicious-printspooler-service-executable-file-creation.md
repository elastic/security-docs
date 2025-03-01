---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-printspooler-service-executable-file-creation.html
---

# Suspicious PrintSpooler Service Executable File Creation [prebuilt-rule-8-4-2-suspicious-printspooler-service-executable-file-creation]

Detects attempts to exploit privilege escalation vulnerabilities related to the Print Spooler service. For more information refer to the following CVE’s - CVE-2020-1048, CVE-2020-1337 and CVE-2020-1300 and verify that the impacted system is patched.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://voidsec.com/cve-2020-1337-printdemon-is-dead-long-live-printdemon/](https://voidsec.com/cve-2020-1337-printdemon-is-dead-long-live-printdemon/)
* [https://www.thezdi.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files](https://www.thezdi.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3555]



## Rule query [_rule_query_4250]

```js
file where event.type == "creation" and
  process.name : "spoolsv.exe" and file.extension : "dll" and
  file.path : ("?:\\Windows\\System32\\*", "?:\\Windows\\SysWOW64\\*") and
  not file.path :
          ("?:\\WINDOWS\\SysWOW64\\PrintConfig.dll",
           "?:\\WINDOWS\\system32\\x5lrs.dll",
           "?:\\WINDOWS\\sysWOW64\\x5lrs.dll",
           "?:\\WINDOWS\\system32\\PrintConfig.dll")
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



