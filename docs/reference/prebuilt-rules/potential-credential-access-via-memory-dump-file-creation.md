---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-credential-access-via-memory-dump-file-creation.html
---

# Potential Credential Access via Memory Dump File Creation [potential-credential-access-via-memory-dump-file-creation]

Identifies the creation or modification of a medium size memory dump file which can indicate an attempt to access credentials from a process memory.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_702]

```js
file where host.os.type == "windows" and event.type == "creation" and

  /* MDMP header */
  file.Ext.header_bytes : "4d444d50*" and file.size >= 30000 and
  not

  (
    (
      process.name : "System" or
      process.executable : (
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\Wermgr.exe",
        "?:\\Windows\\SysWOW64\\Wermgr.exe",
        "?:\\Windows\\System32\\WerFaultSecure.exe",
        "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
        "?:\\Windows\\System32\\WUDFHost.exe",
        "C:\\Windows\\System32\\rdrleakdiag.exe",
        "?:\\Windows\\System32\\Taskmgr.exe",
        "?:\\Windows\\SysWOW64\\Taskmgr.exe",
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Windows\\SystemApps\\*.exe",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin\\zCrashReport64.exe",
        "?:\\Windows\\CCM\\ccmdump.exe",
        "?:\\$WINDOWS.~BT\\Sources\\SetupHost.exe"
      ) and process.code_signature.trusted == true
    ) or
    (
      file.path : (
        "?:\\ProgramData\\Microsoft\\Windows\\WER\\*",
        "?:\\ProgramData\\Microsoft\\WDF\\*",
        "?:\\ProgramData\\Alteryx\\ErrorLogs\\*",
        "?:\\ProgramData\\Goodix\\*",
        "?:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\*",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\logs\\zoomcrash*",
        "?:\\Users\\*\\AppData\\*\\Crashpad\\*",
        "?:\\Users\\*\\AppData\\*\\crashpaddb\\*",
        "?:\\Users\\*\\AppData\\*\\HungReports\\*",
        "?:\\Users\\*\\AppData\\*\\CrashDumps\\*",
        "?:\\Users\\*\\AppData\\*\\NativeCrashReporting\\*",
        "?:\\Program Files (x86)\\*\\Crashpad\\*",
        "?:\\Program Files\\*\\Crashpad\\*"
      ) and (process.code_signature.trusted == true or process.executable == null)
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



