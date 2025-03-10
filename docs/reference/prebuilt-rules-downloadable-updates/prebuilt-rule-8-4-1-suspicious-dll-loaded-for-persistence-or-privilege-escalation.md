---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-suspicious-dll-loaded-for-persistence-or-privilege-escalation.html
---

# Suspicious DLL Loaded for Persistence or Privilege Escalation [prebuilt-rule-8-4-1-suspicious-dll-loaded-for-persistence-or-privilege-escalation]

Identifies the loading of a non Microsoft signed DLL that is missing on a default Windows install (phantom DLL) or one that can be loaded from a different location by a native Windows process. This may be abused to persist or elevate privileges via privileged file write vulnerabilities.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://itm4n.github.io/windows-dll-hijacking-clarified/](https://itm4n.github.io/windows-dll-hijacking-clarified/)
* [http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html](http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.md)
* [https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.md)
* [https://shellz.club/2020/10/16/edgegdi-dll-for-persistence-and-lateral-movement.html](https://shellz.club/2020/10/16/edgegdi-dll-for-persistence-and-lateral-movement.md)
* [https://windows-internals.com/faxing-your-way-to-system/](https://windows-internals.com/faxing-your-way-to-system/)
* [http://waleedassar.blogspot.com/2013/01/wow64logdll.html](http://waleedassar.blogspot.com/2013/01/wow64logdll.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Privilege Escalation
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2848]

## Triage and analysis

## Investigating Suspicious DLL Loaded for Persistence or Privilege Escalation

Attackers can execute malicious code by abusing missing modules that processes try to load, enabling them to escalate
privileges or gain persistence. This rule identifies the loading of a non-Microsoft-signed DLL that is missing on a
default Windows installation or one that can be loaded from a different location by a native Windows process.

### Possible investigation steps

- Examine the DLL signature and identify the process that created it.
  - Investigate any abnormal behaviors by the process such as network connections, registry or file modifications, and
  any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Retrieve the DLL and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently
malicious must be monitored by the security team.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3252]

```js
any where
 (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (
  /* compatible with Elastic Endpoint Library Events */
  (dll.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll")
   and (dll.code_signature.trusted == false or dll.code_signature.exists == false)) or

  /* compatible with Sysmon EventID 7 - Image Load */
  (file.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll")
   and not file.code_signature.status == "Valid")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: DLL Side-Loading
    * ID: T1574.002
    * Reference URL: [https://attack.mitre.org/techniques/T1574/002/](https://attack.mitre.org/techniques/T1574/002/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: DLL Search Order Hijacking
    * ID: T1574.001
    * Reference URL: [https://attack.mitre.org/techniques/T1574/001/](https://attack.mitre.org/techniques/T1574/001/)



