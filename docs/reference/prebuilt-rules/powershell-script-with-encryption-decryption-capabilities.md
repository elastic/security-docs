---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-encryption-decryption-capabilities.html
---

# PowerShell Script with Encryption/Decryption Capabilities [powershell-script-with-encryption-decryption-capabilities]

Identifies the use of Cmdlets and methods related to encryption/decryption of files in PowerShell scripts, which malware and offensive security tools can abuse to encrypt data or decrypt payloads to bypass security solutions.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_804]

**Triage and analysis**

**Investigating PowerShell Script with Encryption/Decryption Capabilities**

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, making it available for use in various environments, creating an attractive way for attackers to execute code.

PowerShell offers encryption and decryption functionalities that attackers can abuse for various purposes, such as concealing payloads, C2 communications, and encrypting data as part of ransomware operations.

**Possible investigation steps**

* Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Examine file or network events from the involved PowerShell process for suspicious behavior.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Evaluate whether the user needs to use PowerShell to complete tasks.

**False positive analysis**

* This is a dual-use mechanism, meaning its usage is not inherently malicious. Analysts can dismiss the alert if the script doesn’t contain malicious functions or potential for abuse, no other suspicious activity was identified, and there are justifications for the execution.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_854]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "Cryptography.AESManaged" or
      "Cryptography.RijndaelManaged" or
      "Cryptography.SHA1Managed" or
      "Cryptography.SHA256Managed" or
      "Cryptography.SHA384Managed" or
      "Cryptography.SHA512Managed" or
      "Cryptography.SymmetricAlgorithm" or
      "PasswordDeriveBytes" or
      "Rfc2898DeriveBytes"
    ) and
    (
      CipherMode and PaddingMode
    ) and
    (
      ".CreateEncryptor" or
      ".CreateDecryptor"
    )
  ) and
  not user.id : "S-1-5-18" and
  not (
    file.name : "Bootstrap.Octopus.FunctionAppenderContext.ps1" and
    powershell.file.script_block_text : ("function Decrypt-Variables" or "github.com/OctopusDeploy")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)



