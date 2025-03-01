---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/writedac-access-on-active-directory-object.html
---

# WRITEDAC Access on Active Directory Object [writedac-access-on-active-directory-object]

Identifies the access on an object with WRITEDAC permissions. With the WRITEDAC permission, the user can perform a Write Discretionary Access Control List (WriteDACL) operation, which is used to modify the access control rules associated with a specific object within Active Directory. Attackers may abuse this privilege to grant themselves or other compromised accounts additional rights, ultimately compromising the target object, resulting in privilege escalation, lateral movement, and persistence.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.security*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors.pdf](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors.pdf)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Active Directory
* Use Case: Active Directory Monitoring
* Rule Type: BBR
* Data Source: System

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_752]

**Setup**

The *Audit Directory Service Access* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Access (Success,Failure)
```


## Rule query [_rule_query_1214]

```js
host.os.type: "windows" and event.action : ("Directory Service Access" or "object-operation-performed") and
  event.code : "4662" and winlog.event_data.AccessMask:"0x40000"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)

* Sub-technique:

    * Name: Windows File and Directory Permissions Modification
    * ID: T1222.001
    * Reference URL: [https://attack.mitre.org/techniques/T1222/001/](https://attack.mitre.org/techniques/T1222/001/)



