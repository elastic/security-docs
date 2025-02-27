---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-compressed-or-archived-into-common-format-by-unsigned-process.html
---

# File Compressed or Archived into Common Format by Unsigned Process [file-compressed-or-archived-into-common-format-by-unsigned-process]

Detects files being compressed or archived into common formats by unsigned processes. This is a common technique used to obfuscate files to evade detection or to staging data for exfiltration.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://en.wikipedia.org/wiki/List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)

**Tags**:

* Data Source: Elastic Defend
* Domain: Endpoint
* OS: macOS
* OS: Windows
* Tactic: Collection
* Rule Type: BBR

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_347]

```js
file where host.os.type == "windows" and event.type in ("creation", "change") and
 process.executable != null and process.code_signature.trusted != true and
 file.Ext.header_bytes : (
                          /* compression formats */
                          "1F9D*",             /* tar zip, tar.z (Lempel-Ziv-Welch algorithm) */
                          "1FA0*",             /* tar zip, tar.z (LZH algorithm) */
                          "425A68*",           /* Bzip2 */
                          "524E4301*",         /* Rob Northen Compression */
                          "524E4302*",         /* Rob Northen Compression */
                          "4C5A4950*",         /* LZIP */
                          "504B0*",            /* ZIP */
                          "526172211A07*",     /* RAR compressed */
                          "44434D0150413330*", /* Windows Update Binary Delta Compression file */
                          "50413330*",         /* Windows Update Binary Delta Compression file */
                          "377ABCAF271C*",     /* 7-Zip */
                          "1F8B*",             /* GZIP */
                          "FD377A585A00*",     /* XZ, tar.xz */
                          "7801*",	           /* zlib: No Compression (no preset dictionary) */
                          "785E*",	           /* zlib: Best speed (no preset dictionary) */
                          "789C*",	           /* zlib: Default Compression (no preset dictionary) */
                          "78DA*", 	           /* zlib: Best Compression (no preset dictionary) */
                          "7820*",	           /* zlib: No Compression (with preset dictionary) */
                          "787D*",	           /* zlib: Best speed (with preset dictionary) */
                          "78BB*",	           /* zlib: Default Compression (with preset dictionary) */
                          "78F9*",	           /* zlib: Best Compression (with preset dictionary) */
                          "62767832*",         /* LZFSE */
                          "28B52FFD*",         /* Zstandard, zst */
                          "5253564B44415441*", /* QuickZip rs compressed archive */
                          "2A2A4143452A2A*",   /* ACE */

                          /* archive formats */
                          "2D686C302D*",       /* lzh */
                          "2D686C352D*",       /* lzh */
                          "303730373037*",     /* cpio */
                          "78617221*",         /* xar */
                          "4F4152*",           /* oar */
                          "49536328*"          /* cab archive */
 )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data Staged
    * ID: T1074
    * Reference URL: [https://attack.mitre.org/techniques/T1074/](https://attack.mitre.org/techniques/T1074/)

* Sub-technique:

    * Name: Local Data Staging
    * ID: T1074.001
    * Reference URL: [https://attack.mitre.org/techniques/T1074/001/](https://attack.mitre.org/techniques/T1074/001/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

* Sub-technique:

    * Name: Archive via Utility
    * ID: T1560.001
    * Reference URL: [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Data Encoding
    * ID: T1132
    * Reference URL: [https://attack.mitre.org/techniques/T1132/](https://attack.mitre.org/techniques/T1132/)

* Sub-technique:

    * Name: Standard Encoding
    * ID: T1132.001
    * Reference URL: [https://attack.mitre.org/techniques/T1132/001/](https://attack.mitre.org/techniques/T1132/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)



