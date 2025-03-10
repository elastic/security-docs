---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unsigned-bits-service-client-process.html
---

# Unsigned BITS Service Client Process [unsigned-bits-service-client-process]

Identifies an unsigned Windows Background Intelligent Transfer Service (BITS) client process. Attackers may abuse BITS functionality to download or upload data using the BITS service.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://web.archive.org/web/20230531215706/https://blog.menasec.net/2021/05/hunting-for-suspicious-usage-of.html](https://web.archive.org/web/20230531215706/https://blog.menasec.net/2021/05/hunting-for-suspicious-usage-of.md)
* [https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-2](https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-2)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1151]

```js
library where dll.name : "Bitsproxy.dll" and process.executable != null and
not process.code_signature.trusted == true and
not process.code_signature.status : ("errorExpired", "errorCode_endpoint*")
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

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)



