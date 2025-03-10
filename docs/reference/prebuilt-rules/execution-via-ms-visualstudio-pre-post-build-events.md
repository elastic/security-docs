---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-via-ms-visualstudio-pre-post-build-events.html
---

# Execution via MS VisualStudio Pre/Post Build Events [execution-via-ms-visualstudio-pre-post-build-events]

Identifies the execution of a command via Microsoft Visual Studio Pre or Post build events. Adversaries may backdoor a trusted visual studio project to execute a malicious command during the project build process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/visualstudio/ide/reference/pre-build-event-post-build-event-command-line-dialog-box?view=vs-2022](https://docs.microsoft.com/en-us/visualstudio/ide/reference/pre-build-event-post-build-event-command-line-dialog-box?view=vs-2022)
* [https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/threat-actor-of-in-tur-est.html](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/threat-actor-of-in-tur-est.md)
* [https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/execution_evasion_visual_studio_prebuild_event.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/execution_evasion_visual_studio_prebuild_event.evtx)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_332]

```js
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.action == "start" and
   process.name : "cmd.exe" and process.parent.name : "MSBuild.exe" and
   process.args : "?:\\Users\\*\\AppData\\Local\\Temp\\tmp*.exec.cmd"] by process.entity_id
  [process where host.os.type == "windows" and event.action == "start" and
    process.name : (
      "cmd.exe", "powershell.exe",
      "MSHTA.EXE", "CertUtil.exe",
      "CertReq.exe", "rundll32.exe",
      "regsvr32.exe", "MSbuild.exe",
      "cscript.exe", "wscript.exe",
      "installutil.exe"
    ) and
    not
    (
      process.name : ("cmd.exe", "powershell.exe") and
      process.args : (
        "*\\vcpkg\\scripts\\buildsystems\\msbuild\\applocal.ps1",
        "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS?",
        "process.versions.node*",
        "?:\\Program Files\\nodejs\\node.exe",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSBuild\\ToolsVersions\\*",
        "*Get-ChildItem*Tipasplus.css*",
        "Build\\GenerateResourceScripts.ps1",
        "Shared\\Common\\..\\..\\BuildTools\\ConfigBuilder.ps1\"",
        "?:\\Projets\\*\\PostBuild\\MediaCache.ps1"
      )
    ) and
    not process.executable : "?:\\Program Files*\\Microsoft Visual Studio\\*\\MSBuild.exe" and
    not (process.name : "cmd.exe" and
         process.command_line :
                  ("*vswhere.exe -property catalog_productSemanticVersion*",
                   "*git log --pretty=format*", "*\\.nuget\\packages\\vswhere\\*",
                   "*Common\\..\\..\\BuildTools\\*"))
  ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



