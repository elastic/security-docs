---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-attempt-to-disable-gatekeeper.html
---

# Attempt to Disable Gatekeeper [prebuilt-rule-8-4-2-attempt-to-disable-gatekeeper]

Detects attempts to disable Gatekeeper on macOS. Gatekeeper is a security feature that’s designed to ensure that only trusted software is run. Adversaries may attempt to disable Gatekeeper before executing malicious code.

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

* [https://support.apple.com/en-us/HT202491](https://support.apple.com/en-us/HT202491)
* [https://community.carbonblack.com/t5/Threat-Advisories-Documents/TAU-TIN-Shlayer-OSX/ta-p/68397](https://community.carbonblack.com/t5/Threat-Advisories-Documents/TAU-TIN-Shlayer-OSX/ta-p/68397)

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

## Rule query [_rule_query_3910]

```js
event.category:process and event.type:(start or process_started) and
  process.args:(spctl and "--master-disable")
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



