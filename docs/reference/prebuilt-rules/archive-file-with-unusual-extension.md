---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/archive-file-with-unusual-extension.html
---

# Archive File with Unusual Extension [archive-file-with-unusual-extension]

Identifies the creation of an archive file with an unusual extension. Attackers may attempt to evade detection by masquerading files using the file extension values used by image, audio, or document file types.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_142]

```js
file where host.os.type == "windows" and event.action != "deletion" and

  /* common archive file headers - Rar, 7z, GZIP, MSCF, XZ, ZIP */
  file.Ext.header_bytes : ("52617221*", "377ABCAF271C*", "1F8B*", "4d534346*", "FD377A585A00*", "504B0304*", "504B0708*") and

  (
    /* common image file extensions */
    file.extension : ("jpg", "jpeg", "emf", "tiff", "gif", "png", "bmp", "ico", "fpx", "eps", "inf") or

    /* common audio and video file extensions */
    file.extension : ("mp3", "wav", "avi", "mpeg", "flv", "wma", "wmv", "mov", "mp4", "3gp") or

    /* common document file extensions */
    (file.extension : ("doc", "docx", "rtf", "ppt", "pptx", "xls", "xlsx") and

    /* exclude ZIP file header values for OPENXML documents */
    not file.Ext.header_bytes : ("504B0304*", "504B0708*"))
  ) and

  not (process.executable : "?:\\Windows\\System32\\inetsrv\\w3wp.exe" and file.path : "?:\\inetpub\\temp\\IIS Temporary Compressed Files\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Masquerade File Type
    * ID: T1036.008
    * Reference URL: [https://attack.mitre.org/techniques/T1036/008/](https://attack.mitre.org/techniques/T1036/008/)



