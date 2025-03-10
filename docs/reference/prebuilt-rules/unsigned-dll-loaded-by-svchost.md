---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unsigned-dll-loaded-by-svchost.html
---

# Unsigned DLL Loaded by Svchost [unsigned-dll-loaded-by-svchost]

Identifies an unsigned library created in the last 5 minutes and subsequently loaded by a shared windows service (svchost). Adversaries may use this technique to maintain persistence or run with System privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion](https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1095]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unsigned DLL Loaded by Svchost**

Svchost.exe is a critical Windows process that hosts multiple services, allowing efficient resource management. Adversaries exploit this by loading unsigned DLLs to gain persistence or execute code with elevated privileges. The detection rule identifies such threats by monitoring DLLs recently created and loaded by svchost, focusing on untrusted signatures and unusual file paths, thus highlighting potential malicious activity.

**Possible investigation steps**

* Review the specific DLL file path and hash (dll.path and dll.hash.sha256) to determine if it is known to be associated with legitimate software or if it is potentially malicious.
* Check the creation time of the DLL (dll.Ext.relative_file_creation_time) to understand the timeline of events and correlate it with other activities on the system around the same time.
* Investigate the process that loaded the DLL (process.executable) to determine if it is a legitimate instance of svchost.exe or if it has been tampered with or replaced.
* Analyze the code signature status (dll.code_signature.trusted and dll.code_signature.status) to verify if the DLL is unsigned or has an untrusted signature, which could indicate tampering or a malicious origin.
* Cross-reference the DLL’s hash (dll.hash.sha256) against known malware databases or threat intelligence sources to identify if it is associated with known threats.
* Examine the system for other indicators of compromise, such as unusual network activity or additional suspicious files, to assess the scope of potential malicious activity.
* Consider isolating the affected system to prevent further potential compromise while conducting a deeper forensic analysis.

**False positive analysis**

* System maintenance or updates may trigger the rule by loading legitimate unsigned DLLs. Users can create exceptions for known update processes or maintenance activities to prevent unnecessary alerts.
* Custom or in-house applications might load unsigned DLLs from unusual paths. Verify the legitimacy of these applications and consider adding their specific paths to the exclusion list if they are deemed safe.
* Security or monitoring tools might use unsigned DLLs for legitimate purposes. Identify these tools and exclude their associated DLLs by hash or path to reduce false positives.
* Temporary files created by legitimate software in monitored directories can be mistaken for threats. Regularly review and update the exclusion list to include hashes of these known benign files.
* Development environments often generate unsigned DLLs during testing phases. Ensure that development paths are excluded from monitoring to avoid false alerts during software development cycles.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the svchost.exe process that loaded the unsigned DLL to stop any ongoing malicious actions.
* Remove the identified unsigned DLL from the system to eliminate the immediate threat.
* Conduct a full antivirus and anti-malware scan on the affected system to detect and remove any additional threats.
* Review and restore any modified system configurations or settings to their original state to ensure system integrity.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for svchost.exe and DLL loading activities to detect similar threats in the future.


## Rule query [_rule_query_1152]

```js
library where host.os.type == "windows" and

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: System Services
    * ID: T1569
    * Reference URL: [https://attack.mitre.org/techniques/T1569/](https://attack.mitre.org/techniques/T1569/)

* Sub-technique:

    * Name: Service Execution
    * ID: T1569.002
    * Reference URL: [https://attack.mitre.org/techniques/T1569/002/](https://attack.mitre.org/techniques/T1569/002/)



