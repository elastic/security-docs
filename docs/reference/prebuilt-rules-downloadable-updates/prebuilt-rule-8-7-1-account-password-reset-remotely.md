---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-account-password-reset-remotely.html
---

# Account Password Reset Remotely [prebuilt-rule-8-7-1-account-password-reset-remotely]

Identifies an attempt to reset a potentially privileged account password remotely. Adversaries may manipulate account passwords to maintain access or evade password duration policies and preserve compromised credentials.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724)
* [https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/](https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4761]

```js
sequence by winlog.computer_name with maxspan=5m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1"] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password" and
   (
    /*
       This rule is very noisy if not scoped to privileged accounts, duplicate the
       rule and add your own naming convention and accounts of interest here.
     */
    winlog.event_data.TargetUserName: ("*Admin*", "*super*", "*SVC*", "*DC0*", "*service*", "*DMZ*", "*ADM*") or
    winlog.event_data.TargetSid : ("S-1-5-21-*-500", "S-1-12-1-*-500")
    )
  ] by winlog.event_data.SubjectLogonId
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



