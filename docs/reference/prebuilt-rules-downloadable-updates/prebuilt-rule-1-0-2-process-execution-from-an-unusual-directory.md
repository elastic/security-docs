---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-process-execution-from-an-unusual-directory.html
---

# Process Execution from an Unusual Directory [prebuilt-rule-1-0-2-process-execution-from-an-unusual-directory]

Identifies process execution from suspicious default Windows directories. This is sometimes done by adversaries to hide malware in trusted paths.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

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
* Execution

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1590]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1838]

```js
process where event.type in ("start", "process_started", "info") and
 /* add suspicious execution paths here */
process.executable : ("C:\\PerfLogs\\*.exe","C:\\Users\\Public\\*.exe","C:\\Users\\Default\\*.exe","C:\\Windows\\Tasks\\*.exe","C:\\Intel\\*.exe","C:\\AMD\\Temp\\*.exe","C:\\Windows\\AppReadiness\\*.exe",
"C:\\Windows\\ServiceState\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\IdentityCRL\\*.exe","C:\\Windows\\Branding\\*.exe","C:\\Windows\\csc\\*.exe",
 "C:\\Windows\\DigitalLocker\\*.exe","C:\\Windows\\en-US\\*.exe","C:\\Windows\\wlansvc\\*.exe","C:\\Windows\\Prefetch\\*.exe","C:\\Windows\\Fonts\\*.exe",
 "C:\\Windows\\diagnostics\\*.exe","C:\\Windows\\TAPI\\*.exe","C:\\Windows\\INF\\*.exe","C:\\Windows\\System32\\Speech\\*.exe","C:\\windows\\tracing\\*.exe",
 "c:\\windows\\IME\\*.exe","c:\\Windows\\Performance\\*.exe","c:\\windows\\intel\\*.exe","c:\\windows\\ms\\*.exe","C:\\Windows\\dot3svc\\*.exe","C:\\Windows\\ServiceProfiles\\*.exe",
 "C:\\Windows\\panther\\*.exe","C:\\Windows\\RemotePackages\\*.exe","C:\\Windows\\OCR\\*.exe","C:\\Windows\\appcompat\\*.exe","C:\\Windows\\apppatch\\*.exe","C:\\Windows\\addins\\*.exe",
 "C:\\Windows\\Setup\\*.exe","C:\\Windows\\Help\\*.exe","C:\\Windows\\SKB\\*.exe","C:\\Windows\\Vss\\*.exe","C:\\Windows\\Web\\*.exe","C:\\Windows\\servicing\\*.exe","C:\\Windows\\CbsTemp\\*.exe",
 "C:\\Windows\\Logs\\*.exe","C:\\Windows\\WaaS\\*.exe","C:\\Windows\\twain_32\\*.exe","C:\\Windows\\ShellExperiences\\*.exe","C:\\Windows\\ShellComponents\\*.exe","C:\\Windows\\PLA\\*.exe",
 "C:\\Windows\\Migration\\*.exe","C:\\Windows\\debug\\*.exe","C:\\Windows\\Cursors\\*.exe","C:\\Windows\\Containers\\*.exe","C:\\Windows\\Boot\\*.exe","C:\\Windows\\bcastdvr\\*.exe",
 "C:\\Windows\\assembly\\*.exe","C:\\Windows\\TextInput\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\schemas\\*.exe","C:\\Windows\\SchCache\\*.exe","C:\\Windows\\Resources\\*.exe",
 "C:\\Windows\\rescache\\*.exe","C:\\Windows\\Provisioning\\*.exe","C:\\Windows\\PrintDialog\\*.exe","C:\\Windows\\PolicyDefinitions\\*.exe","C:\\Windows\\media\\*.exe",
 "C:\\Windows\\Globalization\\*.exe","C:\\Windows\\L2Schemas\\*.exe","C:\\Windows\\LiveKernelReports\\*.exe","C:\\Windows\\ModemLogs\\*.exe","C:\\Windows\\ImmersiveControlPanel\\*.exe") and
 not process.name : ("SpeechUXWiz.exe","SystemSettings.exe","TrustedInstaller.exe","PrintDialog.exe","MpSigStub.exe","LMS.exe","mpam-*.exe")
 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```


