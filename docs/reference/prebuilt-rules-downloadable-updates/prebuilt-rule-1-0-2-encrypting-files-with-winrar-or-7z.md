---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-encrypting-files-with-winrar-or-7z.html
---

# Encrypting Files with WinRar or 7z [prebuilt-rule-1-0-2-encrypting-files-with-winrar-or-7z]

Identifies use of WinRar or 7z to create an encrypted files. Adversaries will often compress and encrypt data in preparation for exfiltration.

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

**References**:

* [https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/](https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1495]

## Triage and analysis

## Investigating Encrypting Files with WinRar or 7z

Attackers may compress and/or encrypt data collected before exfiltration. Compressing the data can help obfuscate the
collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is
being exfiltrated from detection or make exfiltration less apparent upon inspection by a defender.

These steps are usually done in preparation for exfiltration, meaning the attack may be in its final stages.

### Possible investigation steps

- Investigate the script execution chain (parent process tree).
- Retrieve the encrypted file.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check if the password used in the encryption was included in the command line.
- Decrypt the `.rar`/`.zip` and check if the information is sensitive.
- If the password is not available, and the format is `.zip` or the option used in WinRAR is not the `-hp`, list the
file names included in the encrypted file.
- Investigate if the file was transferred to an attacker-controlled server.

## False positive analysis

- Backup software can use these utilities. Check the `process.parent.executable` and
`process.parent.command_line` fields to determine what triggered the encryption.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- If personally identifiable information (PII) or other classified data is involved, investigations into this should be prioritized.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Reset the passwords of the involved accounts.
- Safeguard critical assets to prevent further harm or theft of data.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1729]

```js
process where event.type in ("start", "process_started") and
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



