---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-powershell-share-enumeration-script.html
---

# PowerShell Share Enumeration Script [prebuilt-rule-8-3-2-powershell-share-enumeration-script]

Detects scripts that contain PowerShell functions, structures, or Windows API functions related to windows share enumeration activities. Attackers, mainly ransomware groups, commonly identify and inspect network shares, looking for critical information for encryption and/or exfiltration.

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

* [https://www.advintel.io/post/hunting-for-corporate-insurance-policies-indicators-of-ransom-exfiltrations](https://www.advintel.io/post/hunting-for-corporate-insurance-policies-indicators-of-ransom-exfiltrations)
* [https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/](https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/)
* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2349]

## Triage and analysis

## Investigating PowerShell Share Enumeration Script

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell to enumerate shares to search for sensitive data like documents, scripts, and other kinds
of valuable data for encryption, exfiltration, and lateral movement.

### Possible investigation steps

- Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration
capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Evaluate whether the user needs to use PowerShell to complete tasks.
- Check for additional PowerShell and command line logs that indicate that imported functions were run.
  - Evaluate which information was potentially mapped and accessed by the attacker.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2718]

```js
event.category:process and
  powershell.file.script_block_text:(
    "Invoke-ShareFinder" or
    "Invoke-ShareFinderThreaded" or
    (
      "shi1_netname" and
      "shi1_remark"
    ) or
    (
      "NetShareEnum" and
      "NetApiBufferFree"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

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

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



