---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-cross-site-scripting-xss.html
---

# Potential Cross Site Scripting (XSS) [potential-cross-site-scripting-xss]

Cross-Site Scripting (XSS) is a type of attack in which malicious scripts are injected into trusted websites. In XSS attacks, an attacker uses a benign web application to send malicious code, generally in the form of a browser-side script. This detection rule identifies the potential malicious executions of such browser-side scripts.

**Rule type**: eql

**Rule indices**:

* apm-**-transaction**
* traces-apm*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)

**Tags**:

* Data Source: APM
* Use Case: Threat Detection
* Tactic: Initial Access
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_706]

```js
any where processor.name == "transaction" and
url.fragment : ("<iframe*", "*prompt(*)*", "<script*>", "<svg*>", "*onerror=*", "*javascript*alert*", "*eval*(*)*", "*onclick=*",
"*alert(document.cookie)*", "*alert(document.domain)*","*onresize=*","*onload=*","*onmouseover=*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Drive-by Compromise
    * ID: T1189
    * Reference URL: [https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)



