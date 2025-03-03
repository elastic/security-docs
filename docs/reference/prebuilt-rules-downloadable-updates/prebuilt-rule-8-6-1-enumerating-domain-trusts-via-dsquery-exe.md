---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-enumerating-domain-trusts-via-dsquery-exe.html
---

# Enumerating Domain Trusts via DSQUERY.EXE [prebuilt-rule-8-6-1-enumerating-domain-trusts-via-dsquery-exe]

Identifies the use of dsquery.exe for domain trust discovery purposes. Adversaries may use this command-line utility to enumerate trust relationships that may be used for Lateral Movement opportunities in Windows multi-domain forest environments.

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

* [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))
* [https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3732]



## Rule query [_rule_query_4545]

```js
process where event.type == "start" and
    (process.name : "dsquery.exe" or process.pe.original_file_name: "dsquery.exe") and
    process.args : "*objectClass=trustedDomain*"
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



