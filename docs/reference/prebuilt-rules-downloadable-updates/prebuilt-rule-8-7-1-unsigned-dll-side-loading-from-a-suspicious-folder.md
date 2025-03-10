---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-unsigned-dll-side-loading-from-a-suspicious-folder.html
---

# Unsigned DLL Side-Loading from a Suspicious Folder [prebuilt-rule-8-7-1-unsigned-dll-side-loading-from-a-suspicious-folder]

Identifies a Windows trusted program running from locations often abused by adversaries to masquerade as a trusted program and loading a recently dropped DLL. This behavior may indicate an attempt to evade defenses via side-loading a malicious DLL within the memory space of a signed processes.

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
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3810]



## Rule query [_rule_query_4665]

```js
library where

 process.code_signature.trusted == true and

 (dll.Ext.relative_file_creation_time <= 500 or dll.Ext.relative_file_name_modify_time <= 500) and

  not dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*", "errorChaining") and

      /* Suspicious Paths */
      dll.path : ("?:\\PerfLogs\\*.dll",
                  "?:\\Users\\*\\Pictures\\*.dll",
                  "?:\\Users\\*\\Music\\*.dll",
                  "?:\\Users\\Public\\*.dll",
                  "?:\\Users\\*\\Documents\\*.dll",
                  "?:\\Windows\\Tasks\\*.dll",
                  "?:\\Windows\\System32\\Tasks\\*.dll",
                  "?:\\Intel\\*.dll",
                  "?:\\AMD\\Temp\\*.dll",
                  "?:\\Windows\\AppReadiness\\*.dll",
                  "?:\\Windows\\ServiceState\\*.dll",
                  "?:\\Windows\\security\\*.dll",
		  "?:\\Windows\\System\\*.dll",
                  "?:\\Windows\\IdentityCRL\\*.dll",
                  "?:\\Windows\\Branding\\*.dll",
                  "?:\\Windows\\csc\\*.dll",
                  "?:\\Windows\\DigitalLocker\\*.dll",
                  "?:\\Windows\\en-US\\*.dll",
                  "?:\\Windows\\wlansvc\\*.dll",
                  "?:\\Windows\\Prefetch\\*.dll",
                  "?:\\Windows\\Fonts\\*.dll",
                  "?:\\Windows\\diagnostics\\*.dll",
                  "?:\\Windows\\TAPI\\*.dll",
                  "?:\\Windows\\INF\\*.dll",
                  "?:\\windows\\tracing\\*.dll",
                  "?:\\windows\\IME\\*.dll",
                  "?:\\Windows\\Performance\\*.dll",
                  "?:\\windows\\intel\\*.dll",
                  "?:\\windows\\ms\\*.dll",
                  "?:\\Windows\\dot3svc\\*.dll",
                  "?:\\Windows\\ServiceProfiles\\*.dll",
                  "?:\\Windows\\panther\\*.dll",
                  "?:\\Windows\\RemotePackages\\*.dll",
                  "?:\\Windows\\OCR\\*.dll",
                  "?:\\Windows\\appcompat\\*.dll",
                  "?:\\Windows\\apppatch\\*.dll",
                  "?:\\Windows\\addins\\*.dll",
                  "?:\\Windows\\Setup\\*.dll",
                  "?:\\Windows\\Help\\*.dll",
                  "?:\\Windows\\SKB\\*.dll",
                  "?:\\Windows\\Vss\\*.dll",
                  "?:\\Windows\\Web\\*.dll",
                  "?:\\Windows\\servicing\\*.dll",
                  "?:\\Windows\\CbsTemp\\*.dll",
                  "?:\\Windows\\Logs\\*.dll",
                  "?:\\Windows\\WaaS\\*.dll",
                  "?:\\Windows\\twain_32\\*.dll",
                  "?:\\Windows\\ShellExperiences\\*.dll",
                  "?:\\Windows\\ShellComponents\\*.dll",
                  "?:\\Windows\\PLA\\*.dll",
                  "?:\\Windows\\Migration\\*.dll",
                  "?:\\Windows\\debug\\*.dll",
                  "?:\\Windows\\Cursors\\*.dll",
                  "?:\\Windows\\Containers\\*.dll",
                  "?:\\Windows\\Boot\\*.dll",
                  "?:\\Windows\\bcastdvr\\*.dll",
                  "?:\\Windows\\TextInput\\*.dll",
                  "?:\\Windows\\schemas\\*.dll",
                  "?:\\Windows\\SchCache\\*.dll",
                  "?:\\Windows\\Resources\\*.dll",
                  "?:\\Windows\\rescache\\*.dll",
                  "?:\\Windows\\Provisioning\\*.dll",
                  "?:\\Windows\\PrintDialog\\*.dll",
                  "?:\\Windows\\PolicyDefinitions\\*.dll",
                  "?:\\Windows\\media\\*.dll",
                  "?:\\Windows\\Globalization\\*.dll",
                  "?:\\Windows\\L2Schemas\\*.dll",
                  "?:\\Windows\\LiveKernelReports\\*.dll",
                  "?:\\Windows\\ModemLogs\\*.dll",
                  "?:\\Windows\\ImmersiveControlPanel\\*.dll",
                  "?:\\$Recycle.Bin\\*.dll") and

	 /* DLL loaded from the process.executable current directory */
	 endswith~(substring(dll.path, 0, length(dll.path) - (length(dll.name) + 1)), substring(process.executable, 0, length(process.executable) - (length(process.name) + 1)))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: DLL Side-Loading
    * ID: T1574.002
    * Reference URL: [https://attack.mitre.org/techniques/T1574/002/](https://attack.mitre.org/techniques/T1574/002/)



