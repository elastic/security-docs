---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/process-created-with-a-duplicated-token.html
---

# Process Created with a Duplicated Token [process-created-with-a-duplicated-token]

Identifies the creation of a process impersonating the token of another user logon session. Adversaries may create a new process with a different token to escalate privileges and bypass access controls.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_831]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Created with a Duplicated Token**

In Windows environments, tokens are used to represent user credentials and permissions. Adversaries may duplicate tokens to create processes with elevated privileges, bypassing security controls. The detection rule identifies suspicious process creation by examining token usage patterns, process origins, and recent file modifications, while excluding known legitimate behaviors, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the process name and executable path to determine if it matches any known legitimate applications or if it is potentially malicious. Pay special attention to processes like powershell.exe, cmd.exe, and rundll32.exe.
* Examine the parent process and its executable path to understand the process hierarchy and identify any unusual or unexpected parent-child relationships, especially if the parent is not a typical system process.
* Check the user ID associated with the process to verify if it belongs to a legitimate user or if it appears to be an anomaly, such as a service account being used unexpectedly.
* Investigate the code signature status of the process to determine if it is trusted or if there are any issues like an expired or untrusted signature, which could indicate tampering or a malicious executable.
* Analyze the relative file creation and modification times to assess if the process was created or modified recently, which could suggest a recent compromise or unauthorized change.
* Look for any known exclusions in the query, such as specific command lines or parent processes, to ensure the alert is not a false positive based on legitimate behavior patterns.

**False positive analysis**

* Processes initiated by legitimate system maintenance tools like Windows Update or system repair utilities may trigger the rule. Users can create exceptions for these processes by excluding specific parent-child process relationships that are known to be safe.
* Software installations or updates that involve temporary elevation of privileges might be flagged. Users should consider excluding processes originating from trusted directories like Program Files or Program Files (x86) if they are part of a verified installation or update process.
* Administrative scripts or automation tools that run with elevated privileges could be misidentified. Users can exclude these by specifying trusted code signatures or known script paths in the rule configuration.
* Certain legitimate applications that frequently update or modify files within a short time frame may be mistakenly flagged. Users can adjust the relative file creation or modification time thresholds or exclude specific applications by their executable paths.
* Processes that are part of normal user activity, such as those initiated by explorer.exe, may be incorrectly identified. Users can refine the rule by excluding processes with known benign parent-child relationships involving explorer.exe.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, especially those with duplicated tokens or originating from unexpected parent processes.
* Conduct a thorough review of user accounts and privileges on the affected system to identify any unauthorized changes or escalations. Revoke any unnecessary or suspicious privileges.
* Perform a comprehensive scan of the affected system using updated antivirus and anti-malware tools to detect and remove any malicious software or scripts.
* Review recent file modifications and system logs to identify any additional indicators of compromise or unauthorized activities that may have occurred.
* Restore any altered or corrupted system files from a known good backup to ensure system integrity and functionality.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or accounts have been compromised.


## Rule query [_rule_query_885]

```js
/* This rule is only compatible with Elastic Endpoint 8.4+ */

process where host.os.type == "windows" and event.action == "start" and

 user.id : ("S-1-5-21-*", "S-1-12-1-*") and

 (process.Ext.effective_parent.executable regex~ """[C-Z]:\\Windows\\(System32|SysWOW64)\\[a-zA-Z0-9\-\_\.]+\.exe""" or
  process.Ext.effective_parent.executable : "?:\\Windows\\explorer.exe") and

 (
  process.name : ("powershell.exe", "cmd.exe", "rundll32.exe", "notepad.exe", "net.exe", "ntdsutil.exe",
                  "tasklist.exe", "reg.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "esentutl.exe") or

  ((process.Ext.relative_file_creation_time <= 900 or process.Ext.relative_file_name_modify_time <= 900) and
   not process.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*") and
   not process.executable : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*"))
 ) and
 not (process.name : "rundll32.exe" and
      process.command_line : ("*davclnt.dll,DavSetCookie*", "*?:\\Program Files*",
                              "*\\Windows\\System32\\winethc.dll*", "*\\Windows\\SYSTEM32\\EDGEHTML.dll*",
                              "*shell32.dll,SHCreateLocalServerRunDll*")) and
 not startswith~(process.Ext.effective_parent.name, process.parent.name) and
 not (process.name : "powershell.exe" and process.parent.name : "wmiprvse.exe" and process.Ext.effective_parent.executable : "?:\\Windows\\System32\\wsmprovhost.exe") and
 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\RuntimeBroker.exe" and process.parent.executable : "?:\\Windows\\System32\\sihost.exe") and
 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\sethc.exe" and process.parent.executable : "?:\\Windows\\System32\\svchost.exe") and
 not (process.Ext.effective_parent.executable : "?:\\Windows\\explorer.exe" and
      process.parent.executable : ("?:\\Windows\\System32\\svchost.exe", "?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\twain_32\\*.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Token Impersonation/Theft
    * ID: T1134.001
    * Reference URL: [https://attack.mitre.org/techniques/T1134/001/](https://attack.mitre.org/techniques/T1134/001/)

* Sub-technique:

    * Name: Create Process with Token
    * ID: T1134.002
    * Reference URL: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)



