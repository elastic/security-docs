---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-suspicious-script-with-screenshot-capabilities.html
---

# PowerShell Suspicious Script with Screenshot Capabilities [prebuilt-rule-1-0-2-powershell-suspicious-script-with-screenshot-capabilities]

Detects PowerShell scripts that can take screenshots, which is a common feature in post-exploitation kits and remote access tools (RATs).

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

* [https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen](https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1494]

## Triage and analysis

## Investigating PowerShell Suspicious Script with Screenshot Capabilities

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, which makes
it available for use in various environments and creates an attractive way for attackers to execute code.

Attackers can abuse PowerShell capabilities and take screen captures of desktops to gather information over the course
of an operation.

### Possible investigation steps

- Examine the script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts associated with the user or host in the past 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Investigate if the script stores the captured data locally.
- Investigate if the script contains exfiltration capabilities and the destination of this exfiltration.
- Examine network data to determine if the host communicated with the exfiltration server.

## False positive analysis

- Regular users do not have a business justification for using scripting utilities to take screenshots, which makes false
positives unlikely. In the case of authorized benign true positives (B-TPs), exceptions can be added.

## Related rules

- PowerShell Keylogging Script - bd2c86a0-8b61-4457-ab38-96943984e889

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.
- Reset the password for the user account.

## Config

The 'PowerShell Script Block Logging' logging policy must be enabled.
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

## Rule query [_rule_query_1728]

```js
event.category:process and
  powershell.file.script_block_text : (
    CopyFromScreen and
    ("System.Drawing.Bitmap" or "Drawing.Bitmap")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Screen Capture
    * ID: T1113
    * Reference URL: [https://attack.mitre.org/techniques/T1113/](https://attack.mitre.org/techniques/T1113/)

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



