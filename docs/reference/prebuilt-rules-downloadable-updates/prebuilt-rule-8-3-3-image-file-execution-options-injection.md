---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-image-file-execution-options-injection.html
---

# Image File Execution Options Injection [prebuilt-rule-8-3-3-image-file-execution-options-injection]

The Debugger and SilentProcessExit registry keys can allow an adversary to intercept the execution of files, causing a different process to be executed. This functionality can be abused by an adversary to establish persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3700]

```js
registry where length(registry.data.strings) > 0 and
 registry.path : ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
                  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
                  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
                  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess") and
   /* add FPs here */
 not registry.data.strings regex~ ("""C:\\Program Files( \(x86\))?\\ThinKiosk\\thinkiosk\.exe""", """.*\\PSAppDeployToolkit\\.*""")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Image File Execution Options Injection
    * ID: T1546.012
    * Reference URL: [https://attack.mitre.org/techniques/T1546/012/](https://attack.mitre.org/techniques/T1546/012/)



