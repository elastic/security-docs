---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-discovery-capabilities.html
---

# PowerShell Script with Discovery Capabilities [powershell-script-with-discovery-capabilities]

Identifies the use of Cmdlets and methods related to discovery activities. Attackers can use these to perform various situational awareness related activities, like enumerating users, shares, sessions, domain trusts, groups, etc.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Tactic: Discovery
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_519]

**Setup**

The *PowerShell Script Block Logging* logging policy must be enabled. Steps to implement the logging policy with Advanced Audit Configuration:

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


## Rule query [_rule_query_853]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "Get-ADDefaultDomainPasswordPolicy" or
      "Get-ADDomain" or "Get-ComputerInfo" or
      "Get-Disk" or "Get-DnsClientCache" or
      "Get-GPOReport" or "Get-HotFix" or
      "Get-LocalUser" or "Get-NetFirewallProfile" or
      "get-nettcpconnection" or "Get-NetAdapter" or
      "Get-PhysicalDisk" or "Get-Process" or
      "Get-PSDrive" or "Get-Service" or
      "Get-SmbShare" or "Get-WinEvent"
    ) or
    (
      ("Get-WmiObject" or "gwmi" or "Get-CimInstance" or
       "gcim" or "Management.ManagementObjectSearcher" or
       "System.Management.ManagementClass" or
       "[WmiClass]") and
      (
        "AntiVirusProduct" or "CIM_BIOSElement" or "CIM_ComputerSystem" or "CIM_Product" or "CIM_DiskDrive" or
        "CIM_LogicalDisk" or "CIM_NetworkAdapter" or "CIM_StorageVolume" or "CIM_OperatingSystem" or
        "CIM_Process" or "CIM_Service" or "MSFT_DNSClientCache" or "Win32_BIOS" or "Win32_ComputerSystem" or
        "Win32_ComputerSystemProduct" or "Win32_DiskDrive" or "win32_environment" or "Win32_Group" or
        "Win32_groupuser" or "Win32_IP4RouteTable" or "Win32_logicaldisk" or "Win32_MappedLogicalDisk" or
        "Win32_NetworkAdapterConfiguration" or "win32_ntdomain" or "Win32_OperatingSystem" or
        "Win32_PnPEntity" or "Win32_Process" or "Win32_Product" or "Win32_quickfixengineering" or
        "win32_service" or "Win32_Share" or "Win32_UserAccount"
      )
    ) or
    (
      ("ADSI" and "WinNT") or
      ("Get-ChildItem" and "sysmondrv.sys") or
      ("::GetIPGlobalProperties()" and "GetActiveTcpConnections()") or
      ("ServiceProcess.ServiceController" and "::GetServices") or
      ("Diagnostics.Process" and "::GetProcesses") or
      ("DirectoryServices.Protocols.GroupPolicy" and ".GetGPOReport()") or
      ("DirectoryServices.AccountManagement" and "PrincipalSearcher") or
      ("NetFwTypeLib.NetFwMgr" and "CurrentProfile") or
      ("NetworkInformation.NetworkInterface" and "GetAllNetworkInterfaces") or
      ("Automation.PSDriveInfo") or
      ("Microsoft.Win32.RegistryHive")
    ) or
    (
      "Get-ItemProperty" and
      (
        "\Control\SecurityProviders\WDigest" or
        "\microsoft\windows\currentversion\explorer\runmru" or
        "\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" or
        "\Microsoft\Windows\CurrentVersion\Uninstall" or
        "\Microsoft\Windows\WindowsUpdate" or
        "Policies\Microsoft\Windows\Installer" or
        "Software\Microsoft\Windows\CurrentVersion\Policies" or
        ("\Services\SharedAccess\Parameters\FirewallPolicy" and "EnableFirewall") or
        ("Microsoft\Windows\CurrentVersion\Internet Settings" and "proxyEnable")
      )
    ) or
    (
      ("Directoryservices.Activedirectory" or
      "DirectoryServices.AccountManagement") and
      (
        "Domain Admins" or "DomainControllers" or
        "FindAllGlobalCatalogs" or "GetAllTrustRelationships" or
        "GetCurrentDomain" or "GetCurrentForest"
      ) or
      "DirectoryServices.DirectorySearcher" and
      (
        "samAccountType=805306368" or
        "samAccountType=805306369" or
        "objectCategory=group" or
        "objectCategory=groupPolicyContainer" or
        "objectCategory=site" or
        "objectCategory=subnet" or
        "objectClass=trustedDomain"
      )
    ) or
    (
      "Get-Process" and
      (
        "mcshield" or "windefend" or "savservice" or
        "TMCCSF" or "symantec antivirus" or
        "CSFalcon" or "TmPfw" or "kvoop"
      )
    )
  ) and
  not powershell.file.script_block_text : (
    (
      "__cmdletization_BindCommonParameters" and
      "Microsoft.PowerShell.Core\Export-ModuleMember" and
      "Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter"
    ) or
    "CmdletsToExport=@(\"Add-Content\"," or
    ("cmdletization" and "cdxml-Help.xml")
  ) and
  not user.id : ("S-1-5-18" or "S-1-5-19" or "S-1-5-20")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)

* Sub-technique:

    * Name: Domain Account
    * ID: T1087.002
    * Reference URL: [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)

* Technique:

    * Name: Domain Trust Discovery
    * ID: T1482
    * Reference URL: [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)

* Technique:

    * Name: File and Directory Discovery
    * ID: T1083
    * Reference URL: [https://attack.mitre.org/techniques/T1083/](https://attack.mitre.org/techniques/T1083/)

* Technique:

    * Name: Group Policy Discovery
    * ID: T1615
    * Reference URL: [https://attack.mitre.org/techniques/T1615/](https://attack.mitre.org/techniques/T1615/)

* Technique:

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

* Technique:

    * Name: Password Policy Discovery
    * ID: T1201
    * Reference URL: [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)

* Sub-technique:

    * Name: Security Software Discovery
    * ID: T1518.001
    * Reference URL: [https://attack.mitre.org/techniques/T1518/001/](https://attack.mitre.org/techniques/T1518/001/)

* Technique:

    * Name: Query Registry
    * ID: T1012
    * Reference URL: [https://attack.mitre.org/techniques/T1012/](https://attack.mitre.org/techniques/T1012/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)

* Technique:

    * Name: System Network Connections Discovery
    * ID: T1049
    * Reference URL: [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)

* Technique:

    * Name: System Service Discovery
    * ID: T1007
    * Reference URL: [https://attack.mitre.org/techniques/T1007/](https://attack.mitre.org/techniques/T1007/)

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



