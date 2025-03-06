---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-suspicious-lsass-access-via-malseclogon.html
---

# Suspicious LSASS Access via MalSecLogon [prebuilt-rule-8-4-1-suspicious-lsass-access-via-malseclogon]

Identifies suspicious access to LSASS handle from a call trace pointing to seclogon.dll and with a suspicious access rights value. This may indicate an attempt to leak an LSASS handle via abusing the Secondary Logon service in preparation for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Sysmon Only

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2691]



## Rule query [_rule_query_3081]

```js
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* seclogon service accessing lsass */
  winlog.event_data.CallTrace : "*seclogon.dll*" and process.name : "svchost.exe" and

   /* PROCESS_CREATE_PROCESS & PROCESS_DUP_HANDLE & PROCESS_QUERY_INFORMATION */
  winlog.event_data.GrantedAccess == "0x14c0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



