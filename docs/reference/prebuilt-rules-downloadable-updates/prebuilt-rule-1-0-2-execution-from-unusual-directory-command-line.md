---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-execution-from-unusual-directory-command-line.html
---

# Execution from Unusual Directory - Command Line [prebuilt-rule-1-0-2-execution-from-unusual-directory-command-line]

Identifies process execution from suspicious default Windows directories. This may be abused by adversaries to hide malware in trusted paths.

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1591]

## Triage and analysis

This is related to the `Process Execution from an Unusual Directory rule`.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1839]

```js
process where event.type in ("start", "process_started", "info") and
  process.name : ("wscript.exe",
                  "cscript.exe",
                  "rundll32.exe",
                  "regsvr32.exe",
                  "cmstp.exe",
                  "RegAsm.exe",
                  "installutil.exe",
                  "mshta.exe",
                  "RegSvcs.exe",
                  "powershell.exe",
                  "pwsh.exe",
                  "cmd.exe") and

  /* add suspicious execution paths here */
  process.args : ("C:\\PerfLogs\\*",
                  "C:\\Users\\Public\\*",
                  "C:\\Users\\Default\\*",
                  "C:\\Windows\\Tasks\\*",
                  "C:\\Intel\\*",
                  "C:\\AMD\\Temp\\*",
                  "C:\\Windows\\AppReadiness\\*",
                  "C:\\Windows\\ServiceState\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\IdentityCRL\\*",
                  "C:\\Windows\\Branding\\*",
                  "C:\\Windows\\csc\\*",
                  "C:\\Windows\\DigitalLocker\\*",
                  "C:\\Windows\\en-US\\*",
                  "C:\\Windows\\wlansvc\\*",
                  "C:\\Windows\\Prefetch\\*",
                  "C:\\Windows\\Fonts\\*",
                  "C:\\Windows\\diagnostics\\*",
                  "C:\\Windows\\TAPI\\*",
                  "C:\\Windows\\INF\\*",
                  "C:\\Windows\\System32\\Speech\\*",
                  "C:\\windows\\tracing\\*",
                  "c:\\windows\\IME\\*",
                  "c:\\Windows\\Performance\\*",
                  "c:\\windows\\intel\\*",
                  "c:\\windows\\ms\\*",
                  "C:\\Windows\\dot3svc\\*",
                  "C:\\Windows\\ServiceProfiles\\*",
                  "C:\\Windows\\panther\\*",
                  "C:\\Windows\\RemotePackages\\*",
                  "C:\\Windows\\OCR\\*",
                  "C:\\Windows\\appcompat\\*",
                  "C:\\Windows\\apppatch\\*",
                  "C:\\Windows\\addins\\*",
                  "C:\\Windows\\Setup\\*",
                  "C:\\Windows\\Help\\*",
                  "C:\\Windows\\SKB\\*",
                  "C:\\Windows\\Vss\\*",
                  "C:\\Windows\\Web\\*",
                  "C:\\Windows\\servicing\\*",
                  "C:\\Windows\\CbsTemp\\*",
                  "C:\\Windows\\Logs\\*",
                  "C:\\Windows\\WaaS\\*",
                  "C:\\Windows\\twain_32\\*",
                  "C:\\Windows\\ShellExperiences\\*",
                  "C:\\Windows\\ShellComponents\\*",
                  "C:\\Windows\\PLA\\*",
                  "C:\\Windows\\Migration\\*",
                  "C:\\Windows\\debug\\*",
                  "C:\\Windows\\Cursors\\*",
                  "C:\\Windows\\Containers\\*",
                  "C:\\Windows\\Boot\\*",
                  "C:\\Windows\\bcastdvr\\*",
                  "C:\\Windows\\assembly\\*",
                  "C:\\Windows\\TextInput\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\schemas\\*",
                  "C:\\Windows\\SchCache\\*",
                  "C:\\Windows\\Resources\\*",
                  "C:\\Windows\\rescache\\*",
                  "C:\\Windows\\Provisioning\\*",
                  "C:\\Windows\\PrintDialog\\*",
                  "C:\\Windows\\PolicyDefinitions\\*",
                  "C:\\Windows\\media\\*",
                  "C:\\Windows\\Globalization\\*",
                  "C:\\Windows\\L2Schemas\\*",
                  "C:\\Windows\\LiveKernelReports\\*",
                  "C:\\Windows\\ModemLogs\\*",
                  "C:\\Windows\\ImmersiveControlPanel\\*",
                  "C:\\$Recycle.Bin\\*") and
  not process.parent.executable : ("C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\*\\igfxCUIService*.exe",
                                   "C:\\Windows\\System32\\spacedeskService.exe",
                                   "C:\\Program Files\\Dell\\SupportAssistAgent\\SRE\\SRE.exe") and
  not (process.name : "rundll32.exe" and process.args : ("uxtheme.dll,#64", "PRINTUI.DLL,PrintUIEntry"))
```


