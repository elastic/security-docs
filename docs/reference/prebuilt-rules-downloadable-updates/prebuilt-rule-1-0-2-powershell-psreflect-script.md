---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-psreflect-script.html
---

# PowerShell PSReflect Script [prebuilt-rule-1-0-2-powershell-psreflect-script]

Detects the use of PSReflect in PowerShell scripts. Attackers leverage PSReflect as a library that enables PowerShell to access win32 API functions.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/mattifestation/PSReflect/blob/master/PSReflect.psm1](https://github.com/mattifestation/PSReflect/blob/master/PSReflect.psm1)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1593]

## Triage and analysis

## Investigating PowerShell PSReflect Script

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

PSReflect is a library that enables PowerShell to access win32 API functions in an uncomplicated way. It also helps to
create enums and structs easily—all without touching the disk.

Although this is an interesting project for every developer and admin out there, it is mainly used in the red team and
malware tooling for its capabilities.

Detecting the core implementation of PSReflect means detecting most of the tooling that uses Windows API through
PowerShell, enabling defenders to discover tools being dropped in the environment.

### Possible investigation steps

- Check for additional PowerShell and command-line logs that indicate that imported functions were run.
- Gather the script content that may be split into multiple script blocks (the field `powershell.file.script_block_id`
can be used for filtering), and identify its capabilities.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- PowerShell Suspicious Discovery Related Windows API Functions - 61ac3638-40a3-44b2-855a-985636ca985e
- PowerShell Keylogging Script - bd2c86a0-8b61-4457-ab38-96943984e889
- PowerShell Suspicious Script with Audio Capture Capabilities - 2f2f4939-0b34-40c2-a0a3-844eb7889f43
- Potential Process Injection via PowerShell - 2e29e96a-b67c-455a-afe4-de6183431d0d
- PowerShell Reflection Assembly Load - e26f042e-c590-4e82-8e05-41e81bd822ad
- PowerShell Suspicious Payload Encoded and Compressed - 81fe9dc6-a2d7-4192-a2d8-eed98afc766a
- PowerShell Suspicious Script with Screenshot Capabilities - 959a7353-1129-4aa7-9084-30746b256a70

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host to prevent further post-compromise behavior.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.

## Config

The 'PowerShell Script Block Logging' logging policy must be configured (Enable).

Steps to implement the logging policy with with Advanced Audit Configuration:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

Steps to implement the logging policy via registry:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```

## Rule query [_rule_query_1841]

```js
event.category:process and
  powershell.file.script_block_text:(
    "New-InMemoryModule" or
    "Add-Win32Type" or
    psenum or
    DefineDynamicAssembly or
    DefineDynamicModule or
    "Reflection.TypeAttributes" or
    "Reflection.Emit.OpCodes" or
    "Reflection.Emit.CustomAttributeBuilder" or
    "Runtime.InteropServices.DllImportAttribute"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



