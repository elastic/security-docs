---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-service-imagepath-modification.html
---

# Potential Privilege Escalation via Service ImagePath Modification [potential-privilege-escalation-via-service-imagepath-modification]

Identifies registry modifications to default services that could enable privilege escalation to SYSTEM. Attackers with privileges from groups like Server Operators may change the ImagePath of services to executables under their control or to execute commands.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* winlogbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cube0x0.github.io/Pocing-Beyond-DA/](https://cube0x0.github.io/Pocing-Beyond-DA/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_742]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Service ImagePath Modification**

Windows services are crucial for system operations, often running with high privileges. Adversaries exploit this by altering the ImagePath registry key of services to execute malicious code with elevated privileges. The detection rule identifies suspicious modifications to service ImagePaths, focusing on changes that deviate from standard executable paths, thus flagging potential privilege escalation attempts.

**Possible investigation steps**

* Review the specific registry key and value that triggered the alert to confirm it matches one of the monitored service keys, such as those listed in the query (e.g., *\LanmanServer, *\Winmgmt).
* Examine the modified ImagePath value to determine if it points to a non-standard executable path or a suspicious executable, especially those not located in %systemroot%\system32\.
* Check the process.executable field to identify the process responsible for the registry modification and assess its legitimacy.
* Investigate the user account associated with the modification event to determine if it has elevated privileges, such as membership in the Server Operators group.
* Correlate the event with other logs or alerts to identify any related suspicious activities, such as unexpected service starts or process executions.
* Review recent changes or activities on the host to identify any unauthorized access or configuration changes that could indicate a broader compromise.

**False positive analysis**

* Legitimate software updates or installations may modify service ImagePaths. Users can create exceptions for known update processes or installation paths to prevent false positives.
* System administrators might intentionally change service configurations for maintenance or troubleshooting. Document and exclude these changes by adding exceptions for specific administrator actions or paths.
* Custom scripts or automation tools that modify service settings as part of their operation can trigger alerts. Identify and whitelist these scripts or tools to avoid unnecessary alerts.
* Some third-party security or management software may alter service ImagePaths as part of their functionality. Verify the legitimacy of such software and exclude their known paths from detection.
* Changes made by trusted IT personnel during system configuration or optimization should be logged and excluded from alerts to reduce noise.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified as running from non-standard executable paths, especially those not originating from the system32 directory.
* Restore the modified ImagePath registry key to its original state using a known good configuration or backup.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or persistence mechanisms.
* Review and audit user accounts and group memberships, particularly those with elevated privileges like Server Operators, to ensure no unauthorized changes have been made.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for future modifications to service ImagePath registry keys, focusing on deviations from standard paths to detect similar threats promptly.


## Rule query [_rule_query_789]

```js
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  event.action == "modification" and registry.value == "ImagePath" and
  registry.key : (
    "*\\ADWS", "*\\AppHostSvc", "*\\AppReadiness", "*\\AudioEndpointBuilder", "*\\AxInstSV", "*\\camsvc", "*\\CertSvc",
    "*\\COMSysApp", "*\\CscService", "*\\defragsvc", "*\\DeviceAssociationService", "*\\DeviceInstall", "*\\DevQueryBroker",
    "*\\Dfs", "*\\DFSR", "*\\diagnosticshub.standardcollector.service", "*\\DiagTrack", "*\\DmEnrollmentSvc", "*\\DNS",
    "*\\dot3svc", "*\\Eaphost", "*\\GraphicsPerfSvc", "*\\hidserv", "*\\HvHost", "*\\IISADMIN", "*\\IKEEXT",
    "*\\InstallService", "*\\iphlpsvc", "*\\IsmServ", "*\\LanmanServer", "*\\MSiSCSI", "*\\NcbService", "*\\Netlogon",
    "*\\Netman", "*\\NtFrs", "*\\PlugPlay", "*\\Power", "*\\PrintNotify", "*\\ProfSvc", "*\\PushToInstall", "*\\RSoPProv",
    "*\\sacsvr", "*\\SENS", "*\\SensorDataService", "*\\SgrmBroker", "*\\ShellHWDetection", "*\\shpamsvc", "*\\StorSvc",
    "*\\svsvc", "*\\swprv", "*\\SysMain", "*\\Themes", "*\\TieringEngineService", "*\\TokenBroker", "*\\TrkWks",
    "*\\UALSVC", "*\\UserManager", "*\\vm3dservice", "*\\vmicguestinterface", "*\\vmicheartbeat", "*\\vmickvpexchange",
    "*\\vmicrdv", "*\\vmicshutdown", "*\\vmicvmsession", "*\\vmicvss", "*\\vmvss", "*\\VSS", "*\\w3logsvc", "*\\W3SVC",
    "*\\WalletService", "*\\WAS", "*\\wercplsupport", "*\\WerSvc", "*\\Winmgmt", "*\\wisvc", "*\\wmiApSrv",
    "*\\WPDBusEnum", "*\\WSearch"
  ) and
  not (
    registry.data.strings : (
        "?:\\Windows\\system32\\*.exe",
        "%systemroot%\\system32\\*.exe",
        "%windir%\\system32\\*.exe",
        "%SystemRoot%\\system32\\svchost.exe -k *",
        "%windir%\\system32\\svchost.exe -k *"
    ) and
        not registry.data.strings : (
            "*\\cmd.exe",
            "*\\cscript.exe",
            "*\\ieexec.exe",
            "*\\iexpress.exe",
            "*\\installutil.exe",
            "*\\Microsoft.Workflow.Compiler.exe",
            "*\\msbuild.exe",
            "*\\mshta.exe",
            "*\\msiexec.exe",
            "*\\msxsl.exe",
            "*\\net.exe",
            "*\\powershell.exe",
            "*\\pwsh.exe",
            "*\\reg.exe",
            "*\\RegAsm.exe",
            "*\\RegSvcs.exe",
            "*\\regsvr32.exe",
            "*\\rundll32.exe",
            "*\\vssadmin.exe",
            "*\\wbadmin.exe",
            "*\\wmic.exe",
            "*\\wscript.exe"
        )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Services Registry Permissions Weakness
    * ID: T1574.011
    * Reference URL: [https://attack.mitre.org/techniques/T1574/011/](https://attack.mitre.org/techniques/T1574/011/)

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



