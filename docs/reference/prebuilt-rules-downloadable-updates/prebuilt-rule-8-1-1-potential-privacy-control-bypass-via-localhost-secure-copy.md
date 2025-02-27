---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-potential-privacy-control-bypass-via-localhost-secure-copy.html
---

# Potential Privacy Control Bypass via Localhost Secure Copy [prebuilt-rule-8-1-1-potential-privacy-control-bypass-via-localhost-secure-copy]

Identifies use of the Secure Copy Protocol (SCP) to copy files locally by abusing the auto addition of the Secure Shell Daemon (sshd) to the authorized application list for Full Disk Access. This may indicate attempts to bypass macOS privacy controls to access sensitive files.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware—​infects-xcode-projects—​uses-0-days.html](https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware—​infects-xcode-projects—​uses-0-days.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Privilege Escalation
* Defense Evasion

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1695]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1976]

```js
process where event.type in ("start", "process_started") and
 process.name:"scp" and
 process.args:"StrictHostKeyChecking=no" and
 process.command_line:("scp *localhost:/*", "scp *127.0.0.1:/*") and
 not process.args:"vagrant@*127.0.0.1*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)



