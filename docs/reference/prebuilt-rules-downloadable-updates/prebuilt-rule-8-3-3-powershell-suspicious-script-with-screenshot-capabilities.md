---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-powershell-suspicious-script-with-screenshot-capabilities.html
---

# PowerShell Suspicious Script with Screenshot Capabilities [prebuilt-rule-8-3-3-powershell-suspicious-script-with-screenshot-capabilities]

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
* Investigation Guide
* PowerShell

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2990]

## Triage and analysis

## Investigating PowerShell Suspicious Script with Screenshot Capabilities

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, which makes it available for use in various environments and creates an attractive way for attackers to execute code.

Attackers can abuse PowerShell capabilities and take screen captures of desktops to gather information over the course of an operation.

### Possible investigation steps

- Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Examine file or network events from the involved PowerShell process for suspicious behavior.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Evaluate whether the user needs to use PowerShell to complete tasks.
- Investigate if the script stores the captured data locally.
- Investigate if the script contains exfiltration capabilities and the destination of this exfiltration.
- Assess network data to determine if the host communicated with the exfiltration server.

## False positive analysis

- Regular users do not have a business justification for using scripting utilities to take screenshots, which makes false positives unlikely. In the case of authorized benign true positives (B-TPs), exceptions can be added.

## Related rules

- PowerShell Keylogging Script - bd2c86a0-8b61-4457-ab38-96943984e889

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3483]

```js
event.category:process and
  powershell.file.script_block_text : (
    CopyFromScreen and
    ("System.Drawing.Bitmap" or "Drawing.Bitmap")
  ) and not user.id : "S-1-5-18"
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



