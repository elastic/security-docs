---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-powershell-engine-imageload.html
---

# Suspicious PowerShell Engine ImageLoad [prebuilt-rule-1-0-2-suspicious-powershell-engine-imageload]

Identifies the PowerShell engine being invoked by unexpected processes. Rather than executing PowerShell functionality with powershell.exe, some attackers do this to operate more stealthily.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
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

## Investigation guide [_investigation_guide_1598]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1847]

```js
library where dll.name : ("System.Management.Automation.ni.dll", "System.Management.Automation.dll") and
/* add false positives relevant to your environment here */
not process.executable : ("C:\\Windows\\System32\\RemoteFXvGPUDisablement.exe", "C:\\Windows\\System32\\sdiagnhost.exe") and
not process.executable regex~ """C:\\Program Files( \(x86\))?\\*\.exe""" and
  not process.name :
  (
    "Altaro.SubAgent.exe",
    "AppV_Manage.exe",
    "azureadconnect.exe",
    "CcmExec.exe",
    "configsyncrun.exe",
    "choco.exe",
    "ctxappvservice.exe",
    "DVLS.Console.exe",
    "edgetransport.exe",
    "exsetup.exe",
    "forefrontactivedirectoryconnector.exe",
    "InstallUtil.exe",
    "JenkinsOnDesktop.exe",
    "Microsoft.EnterpriseManagement.ServiceManager.UI.Console.exe",
    "mmc.exe",
    "mscorsvw.exe",
    "msexchangedelivery.exe",
    "msexchangefrontendtransport.exe",
    "msexchangehmworker.exe",
    "msexchangesubmission.exe",
    "msiexec.exe",
    "MsiExec.exe",
    "noderunner.exe",
    "NServiceBus.Host.exe",
    "NServiceBus.Host32.exe",
    "NServiceBus.Hosting.Azure.HostProcess.exe",
    "OuiGui.WPF.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "SCCMCliCtrWPF.exe",
    "ScriptEditor.exe",
    "ScriptRunner.exe",
    "sdiagnhost.exe",
    "servermanager.exe",
    "setup100.exe",
    "ServiceHub.VSDetouredHost.exe",
    "SPCAF.Client.exe",
    "SPCAF.SettingsEditor.exe",
    "SQLPS.exe",
    "telemetryservice.exe",
    "UMWorkerProcess.exe",
    "w3wp.exe",
    "wsmprovhost.exe"
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



