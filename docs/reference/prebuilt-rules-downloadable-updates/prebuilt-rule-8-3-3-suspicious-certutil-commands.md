---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-certutil-commands.html
---

# Suspicious CertUtil Commands [prebuilt-rule-8-3-3-suspicious-certutil-commands]

Identifies suspicious commands being used with certutil.exe. CertUtil is a native Windows component which is part of Certificate Services. CertUtil is often abused by attackers to live off the land for stealthier command and control or data exfiltration.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/Moriarty_Meng/status/984380793383370752](https://twitter.com/Moriarty_Meng/status/984380793383370752)
* [https://twitter.com/egre55/status/1087685529016193025](https://twitter.com/egre55/status/1087685529016193025)
* [https://www.sysadmins.lv/blog-en/certutil-tips-and-tricks-working-with-x509-file-format.aspx](https://www.sysadmins.lv/blog-en/certutil-tips-and-tricks-working-with-x509-file-format.aspx)
* [https://docs.microsoft.com/en-us/archive/blogs/pki/basic-crl-checking-with-certutil](https://docs.microsoft.com/en-us/archive/blogs/pki/basic-crl-checking-with-certutil)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3082]



## Rule query [_rule_query_3594]

```js
process where event.type == "start" and
  (process.name : "certutil.exe" or process.pe.original_file_name == "CertUtil.exe") and
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
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



