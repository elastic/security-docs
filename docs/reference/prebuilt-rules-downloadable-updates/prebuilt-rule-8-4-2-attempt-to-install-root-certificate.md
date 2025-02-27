---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-attempt-to-install-root-certificate.html
---

# Attempt to Install Root Certificate [prebuilt-rule-8-4-2-attempt-to-install-root-certificate]

Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to their command and control servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root’s chain of trust that have been signed by the root certificate.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://ss64.com/osx/security-cert.html](https://ss64.com/osx/security-cert.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3911]

```js
event.category:process and event.type:(start or process_started) and
  process.name:security and process.args:"add-trusted-cert" and
  not process.parent.executable:("/Library/Bitdefender/AVP/product/bin/BDCoreIssues" or "/Applications/Bitdefender/SecurityNetworkInstallerApp.app/Contents/MacOS/SecurityNetworkInstallerApp"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Sub-technique:

    * Name: Install Root Certificate
    * ID: T1553.004
    * Reference URL: [https://attack.mitre.org/techniques/T1553/004/](https://attack.mitre.org/techniques/T1553/004/)



