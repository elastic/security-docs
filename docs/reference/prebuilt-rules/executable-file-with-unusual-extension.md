---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/executable-file-with-unusual-extension.html
---

# Executable File with Unusual Extension [executable-file-with-unusual-extension]

Identifies the creation or modification of an executable file with an unexpected file extension. Attackers may attempt to evade detection by masquerading files using the file extension values used by image, audio, or document file types.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_321]

```js
file where host.os.type == "windows" and event.action != "deletion" and

 /* MZ header or its common base64 equivalent TVqQ */
 file.Ext.header_bytes : ("4d5a*", "54567151*") and

 (
   /* common image file extensions */
   file.extension : ("jpg", "jpeg", "emf", "tiff", "gif", "png", "bmp", "fpx", "eps", "svg", "inf") or

   /* common audio and video file extensions */
   file.extension : ("mp3", "wav", "avi", "mpeg", "flv", "wma", "wmv", "mov", "mp4", "3gp") or

   /* common document file extensions */
   file.extension : ("txt", "pdf", "doc", "docx", "rtf", "ppt", "pptx", "xls", "xlsx", "hwp", "html")
  ) and
  not process.pid == 4 and
  not process.executable : "?:\\Program Files (x86)\\Trend Micro\\Client Server Security Agent\\Ntrtscan.exe"
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



