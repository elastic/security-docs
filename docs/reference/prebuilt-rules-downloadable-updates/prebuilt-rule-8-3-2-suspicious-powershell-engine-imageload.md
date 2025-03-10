---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-suspicious-powershell-engine-imageload.html
---

# Suspicious PowerShell Engine ImageLoad [prebuilt-rule-8-3-2-suspicious-powershell-engine-imageload]

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
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2504]

## Triage and analysis

## Investigating Suspicious PowerShell Engine ImageLoad

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell without having to execute `PowerShell.exe` directly. This technique, often called
"PowerShell without PowerShell," works by using the underlying System.Management.Automation namespace and can bypass
application allowlisting and PowerShell security features.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file
modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Inspect the host for suspicious or abnormal behavior in the alert timeframe.
- Retrieve the implementation (DLL, executable, etc.) and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell `Get-FileHash` cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity can happen legitimately. Some vendors have their own PowerShell implementations that are shipped with
some products. These benign true positives (B-TPs) can be added as exceptions if necessary after analysis.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).



If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_2877]

```js
any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (dll.name : ("System.Management.Automation.ni.dll", "System.Management.Automation.dll") or
  file.name : ("System.Management.Automation.ni.dll", "System.Management.Automation.dll")) and

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



