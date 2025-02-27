---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-execution-with-explicit-credentials-via-scripting.html
---

# Execution with Explicit Credentials via Scripting [prebuilt-rule-8-4-2-execution-with-explicit-credentials-via-scripting]

Identifies execution of the security_authtrampoline process via a scripting interpreter. This occurs when programs use AuthorizationExecute-WithPrivileges from the Security.framework to run another program with root privileges. It should not be run by itself, as this is a sign of execution with explicit logon credentials.

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

* [https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)
* [https://www.manpagez.com/man/8/security_authtrampoline/](https://www.manpagez.com/man/8/security_authtrampoline/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Execution
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3955]

```js
event.category:process and event.type:(start or process_started) and
 process.name:"security_authtrampoline" and
 process.parent.name:(osascript or com.apple.automator.runner or sh or bash or dash or zsh or python* or Python or perl* or php* or ruby or pwsh)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Elevated Execution with Prompt
    * ID: T1548.004
    * Reference URL: [https://attack.mitre.org/techniques/T1548/004/](https://attack.mitre.org/techniques/T1548/004/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



