---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-certutil-commands.html
---

# Suspicious CertUtil Commands [prebuilt-rule-1-0-2-suspicious-certutil-commands]

Identifies suspicious commands being used with certutil.exe. CertUtil is a native Windows component which is part of Certificate Services. CertUtil is often abused by attackers to live off the land for stealthier command and control or data exfiltration.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

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

**Version**: 13

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1563]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1805]

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



