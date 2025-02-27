---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-enumerating-domain-trusts-via-nltest-exe.html
---

# Enumerating Domain Trusts via NLTEST.EXE [prebuilt-rule-8-4-2-enumerating-domain-trusts-via-nltest-exe]

Identifies the use of nltest.exe for domain trust discovery purposes. Adversaries may use this command-line utility to enumerate domain trusts and gain insight into trust relationships, as well as the state of Domain Controller (DC) replication in a Microsoft Windows NT Domain.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
* [https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3446]



## Rule query [_rule_query_4107]

```js
process where event.type == "start" and
    process.name : "nltest.exe" and process.args : (
        "/DCLIST:*", "/DCNAME:*", "/DSGET*",
        "/LSAQUERYFTI:*", "/PARENTDOMAIN",
        "/DOMAIN_TRUSTS", "/BDC_QUERY:*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Domain Trust Discovery
    * ID: T1482
    * Reference URL: [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)



