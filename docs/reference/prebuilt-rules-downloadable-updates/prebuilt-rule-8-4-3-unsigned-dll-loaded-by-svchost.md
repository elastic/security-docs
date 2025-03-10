---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-unsigned-dll-loaded-by-svchost.html
---

# Unsigned DLL Loaded by Svchost [prebuilt-rule-8-4-3-unsigned-dll-loaded-by-svchost]

Identifies an unsigned library created in the last 5 minutes and subsequently loaded by a shared windows service (svchost). Adversaries may use this technique to maintain persistence or run with System privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4298]

```js
library where

 process.executable :
     ("?:\\Windows\\System32\\svchost.exe", "?:\\Windows\\Syswow64\\svchost.exe") and

 dll.code_signature.trusted != true and

 not dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*") and

 dll.hash.sha256 != null and

 (
       /* DLL created within 5 minutes of the library load event - compatible with Elastic Endpoint 8.4+ */
       dll.Ext.relative_file_creation_time <= 300 or

       /* unusual paths */
       dll.path :("?:\\ProgramData\\*",
                  "?:\\Users\\*",
                  "?:\\PerfLogs\\*",
                  "?:\\Windows\\Tasks\\*",
                  "?:\\Intel\\*",
                  "?:\\AMD\\Temp\\*",
                  "?:\\Windows\\AppReadiness\\*",
                  "?:\\Windows\\ServiceState\\*",
                  "?:\\Windows\\security\\*",
                  "?:\\Windows\\IdentityCRL\\*",
                  "?:\\Windows\\Branding\\*",
                  "?:\\Windows\\csc\\*",
                  "?:\\Windows\\DigitalLocker\\*",
                  "?:\\Windows\\en-US\\*",
                  "?:\\Windows\\wlansvc\\*",
                  "?:\\Windows\\Prefetch\\*",
                  "?:\\Windows\\Fonts\\*",
                  "?:\\Windows\\diagnostics\\*",
                  "?:\\Windows\\TAPI\\*",
                  "?:\\Windows\\INF\\*",
                  "?:\\Windows\\System32\\Speech\\*",
                  "?:\\windows\\tracing\\*",
                  "?:\\windows\\IME\\*",
                  "?:\\Windows\\Performance\\*",
                  "?:\\windows\\intel\\*",
                  "?:\\windows\\ms\\*",
                  "?:\\Windows\\dot3svc\\*",
                  "?:\\Windows\\panther\\*",
                  "?:\\Windows\\RemotePackages\\*",
                  "?:\\Windows\\OCR\\*",
                  "?:\\Windows\\appcompat\\*",
                  "?:\\Windows\\apppatch\\*",
                  "?:\\Windows\\addins\\*",
                  "?:\\Windows\\Setup\\*",
                  "?:\\Windows\\Help\\*",
                  "?:\\Windows\\SKB\\*",
                  "?:\\Windows\\Vss\\*",
                  "?:\\Windows\\servicing\\*",
                  "?:\\Windows\\CbsTemp\\*",
                  "?:\\Windows\\Logs\\*",
                  "?:\\Windows\\WaaS\\*",
                  "?:\\Windows\\twain_32\\*",
                  "?:\\Windows\\ShellExperiences\\*",
                  "?:\\Windows\\ShellComponents\\*",
                  "?:\\Windows\\PLA\\*",
                  "?:\\Windows\\Migration\\*",
                  "?:\\Windows\\debug\\*",
                  "?:\\Windows\\Cursors\\*",
                  "?:\\Windows\\Containers\\*",
                  "?:\\Windows\\Boot\\*",
                  "?:\\Windows\\bcastdvr\\*",
                  "?:\\Windows\\TextInput\\*",
                  "?:\\Windows\\security\\*",
                  "?:\\Windows\\schemas\\*",
                  "?:\\Windows\\SchCache\\*",
                  "?:\\Windows\\Resources\\*",
                  "?:\\Windows\\rescache\\*",
                  "?:\\Windows\\Provisioning\\*",
                  "?:\\Windows\\PrintDialog\\*",
                  "?:\\Windows\\PolicyDefinitions\\*",
                  "?:\\Windows\\media\\*",
                  "?:\\Windows\\Globalization\\*",
                  "?:\\Windows\\L2Schemas\\*",
                  "?:\\Windows\\LiveKernelReports\\*",
                  "?:\\Windows\\ModemLogs\\*",
                  "?:\\Windows\\ImmersiveControlPanel\\*",
                  "?:\\$Recycle.Bin\\*")
  ) and

  not dll.hash.sha256 :
            ("3ed33e71641645367442e65dca6dab0d326b22b48ef9a4c2a2488e67383aa9a6",
             "b4db053f6032964df1b254ac44cb995ffaeb4f3ade09597670aba4f172cf65e4",
             "214c75f678bc596bbe667a3b520aaaf09a0e50c364a28ac738a02f867a085eba",
             "23aa95b637a1bf6188b386c21c4e87967ede80242327c55447a5bb70d9439244",
             "5050b025909e81ae5481db37beb807a80c52fc6dd30c8aa47c9f7841e2a31be7")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



