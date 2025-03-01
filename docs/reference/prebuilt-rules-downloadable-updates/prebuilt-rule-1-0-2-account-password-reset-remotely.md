---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-account-password-reset-remotely.html
---

# Account Password Reset Remotely [prebuilt-rule-1-0-2-account-password-reset-remotely]

Identifies an attempt to reset an account password remotely. Adversaries may manipulate account passwords to maintain access or evade password duration policies and preserve compromised credentials.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724)
* [https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/](https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1897]

```js
sequence by host.id with maxspan=5m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1"] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password"] by winlog.event_data.SubjectLogonId
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



