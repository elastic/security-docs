---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-encrypting-files-with-winrar-or-7z.html
---

# Encrypting Files with WinRar or 7z [prebuilt-rule-8-4-2-encrypting-files-with-winrar-or-7z]

Identifies use of WinRar or 7z to create an encrypted files. Adversaries will often compress and encrypt data in preparation for exfiltration.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/](https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3336]

## Triage and analysis

## Investigating Encrypting Files with WinRar or 7z

Attackers may compress and/or encrypt data collected before exfiltration. Compressing the data can help obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less apparent upon inspection by a defender.

These steps are usually done in preparation for exfiltration, meaning the attack may be in its final stages.

### Possible investigation steps

- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Retrieve the encrypted file.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check if the password used in the encryption was included in the command line.
- Decrypt the `.rar`/`.zip` and check if the information is sensitive.
- If the password is not available, and the format is `.zip` or the option used in WinRAR is not the `-hp`, list the file names included in the encrypted file.
- Investigate if the file was transferred to an attacker-controlled server.

## False positive analysis

- Backup software can use these utilities. Check the `process.parent.executable` and `process.parent.command_line` fields to determine what triggered the encryption.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Prioritize cases that involve personally identifiable information (PII) or other classified data.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3973]

```js
process where event.type == "start" and
  ((process.name:"rar.exe" or process.code_signature.subject_name == "win.rar GmbH" or
      process.pe.original_file_name == "Command line RAR") and
    process.args == "a" and process.args : ("-hp*", "-p*", "-dw", "-tb", "-ta", "/hp*", "/p*", "/dw", "/tb", "/ta"))

  or
  (process.pe.original_file_name in ("7z.exe", "7za.exe") and
     process.args == "a" and process.args : ("-p*", "-sdel"))

  /* uncomment if noisy for backup software related FPs */
  /* not process.parent.executable : ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe") */
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

* Sub-technique:

    * Name: Archive via Utility
    * ID: T1560.001
    * Reference URL: [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)



