---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-powershell-script-with-encryption-decryption-capabilities.html
---

# PowerShell Script with Encryption/Decryption Capabilities [prebuilt-rule-8-7-1-powershell-script-with-encryption-decryption-capabilities]

Identifies the use of Cmdlets and methods related to encryption/decryption of files in PowerShell scripts, which malware and offensive security tools can abuse to encrypt data or decrypt payloads to bypass security solutions.

**Rule type**: query

**Rule indices**:

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
* Defense Evasion
* PowerShell

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4663]

```js
event.category:process and
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
  ) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)



