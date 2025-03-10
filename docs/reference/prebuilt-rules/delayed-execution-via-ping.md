---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/delayed-execution-via-ping.html
---

# Delayed Execution via Ping [delayed-execution-via-ping]

Identifies the execution of commonly abused Windows utilities via a delayed Ping execution. This behavior is often observed during malware installation and is consistent with an attacker attempting to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

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
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_264]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Delayed Execution via Ping**

Ping, a network utility, can be misused by attackers to delay execution of malicious commands, aiding in evasion. Adversaries may use ping to introduce pauses, allowing them to execute harmful scripts or binaries stealthily. The detection rule identifies suspicious ping usage followed by execution of known malicious utilities, flagging potential threats by monitoring specific command patterns and excluding benign processes.

**Possible investigation steps**

* Review the process tree to understand the sequence of events, focusing on the parent-child relationship between cmd.exe, ping.exe, and any subsequent suspicious processes like rundll32.exe or powershell.exe.
* Examine the command line arguments used with ping.exe to determine the delay introduced and assess if it aligns with typical malicious behavior.
* Investigate the user account associated with the process execution, especially if the user.id is not S-1-5-18, to determine if the account has been compromised or is being misused.
* Check the file path and code signature of any executables launched from the user’s AppData directory to verify if they are trusted or potentially malicious.
* Analyze the command line arguments and working directory of any suspicious processes to identify any known malicious patterns or scripts being executed.
* Correlate the alert with any other recent alerts or logs from the same host or user to identify potential patterns or ongoing malicious activity.

**False positive analysis**

* Legitimate administrative scripts or maintenance tasks may use ping to introduce delays, especially in batch files executed by system administrators. To handle this, identify and exclude specific scripts or command lines that are known to be safe.
* Software installations or updates might use ping for timing purposes. Review the command lines and parent processes involved, and create exceptions for trusted software paths or signatures.
* Automated testing environments may use ping to simulate network latency or wait for services to start. Exclude these processes by identifying the testing framework or environment and adding it to the exception list.
* Some legitimate applications might use ping as part of their normal operation. Monitor these applications and, if verified as safe, exclude their specific command patterns or executable paths.
* Regularly review and update the exception list to ensure it reflects the current environment and any new legitimate use cases that arise.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified in the alert, such as those involving ping.exe followed by the execution of known malicious utilities.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malware or unauthorized software.
* Review and analyze the command history and logs of the affected system to understand the scope of the attack and identify any additional compromised systems.
* Restore the system from a known good backup if malware removal is not feasible or if the system’s integrity is in question.
* Implement application whitelisting to prevent unauthorized execution of scripts and binaries, focusing on the utilities identified in the alert.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_274]

```js
sequence by process.parent.entity_id with maxspan=1m
  [process where host.os.type == "windows" and event.action == "start" and process.name : "ping.exe" and
   process.args : "-n" and process.parent.name : "cmd.exe" and not user.id : "S-1-5-18"]
  [process where host.os.type == "windows" and event.action == "start" and
   process.parent.name : "cmd.exe" and
   (
        process.name : (
            "rundll32.exe", "powershell.exe",
            "mshta.exe", "msbuild.exe",
            "certutil.exe", "regsvr32.exe",
            "powershell.exe", "cscript.exe",
            "wscript.exe", "wmic.exe",
            "installutil.exe", "msxsl.exe",
            "Microsoft.Workflow.Compiler.exe",
            "ieexec.exe", "iexpress.exe",
            "RegAsm.exe", "installutil.exe",
            "RegSvcs.exe", "RegAsm.exe"
        ) or
        (process.executable : "?:\\Users\\*\\AppData\\*.exe" and not process.code_signature.trusted == true)
    ) and

    not process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*") and
    not (process.name : ("openssl.exe", "httpcfg.exe", "certutil.exe") and process.parent.command_line : "*ScreenConnectConfigurator.cmd*") and
    not (process.pe.original_file_name : "DPInst.exe" and process.command_line : "driver\\DPInst_x64  /f ") and
    not (process.name : "powershell.exe" and process.args : "Write-Host ======*") and
    not (process.name : "wscript.exe" and process.args : "launchquiet_args.vbs" and process.parent.args : "?:\\Windows\\TempInst\\7z*") and
    not (process.name : "regsvr32.exe" and process.args : ("?:\\windows\\syswow64\\msxml?.dll", "msxml?.dll", "?:\\Windows\\SysWOW64\\mschrt20.ocx")) and
    not (process.name : "wscript.exe" and
         process.working_directory :
                    ("?:\\Windows\\TempInst\\*",
                     "?:\\Users\\*\\AppData\\Local\\Temp\\BackupBootstrapper\\Logs\\",
                     "?:\\Users\\*\\AppData\\Local\\Temp\\QBTools\\"))
    ]
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

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Script Proxy Execution
    * ID: T1216
    * Reference URL: [https://attack.mitre.org/techniques/T1216/](https://attack.mitre.org/techniques/T1216/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: CMSTP
    * ID: T1218.003
    * Reference URL: [https://attack.mitre.org/techniques/T1218/003/](https://attack.mitre.org/techniques/T1218/003/)

* Sub-technique:

    * Name: InstallUtil
    * ID: T1218.004
    * Reference URL: [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)

* Sub-technique:

    * Name: Regsvcs/Regasm
    * ID: T1218.009
    * Reference URL: [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)

* Sub-technique:

    * Name: Regsvr32
    * ID: T1218.010
    * Reference URL: [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)

* Technique:

    * Name: XSL Script Processing
    * ID: T1220
    * Reference URL: [https://attack.mitre.org/techniques/T1220/](https://attack.mitre.org/techniques/T1220/)

* Technique:

    * Name: Virtualization/Sandbox Evasion
    * ID: T1497
    * Reference URL: [https://attack.mitre.org/techniques/T1497/](https://attack.mitre.org/techniques/T1497/)

* Sub-technique:

    * Name: Time Based Evasion
    * ID: T1497.003
    * Reference URL: [https://attack.mitre.org/techniques/T1497/003/](https://attack.mitre.org/techniques/T1497/003/)



