---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-potential-exfiltration-via-certreq.html
---

# Potential Exfiltration via Certreq [prebuilt-rule-8-4-3-potential-exfiltration-via-certreq]

Identifies Certreq making an HTTP Post request. Adversaries could abuse Certreq to exfiltrate data to a remote URL.

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

* [https://lolbas-project.github.io/lolbas/Binaries/Certreq/](https://lolbas-project.github.io/lolbas/Binaries/Certreq/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Command and Control
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4275]

```js
process where event.type == "start" and
 (process.name : "CertReq.exe" or process.pe.original_file_name == "CertReq.exe") and process.args : "-Post"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



