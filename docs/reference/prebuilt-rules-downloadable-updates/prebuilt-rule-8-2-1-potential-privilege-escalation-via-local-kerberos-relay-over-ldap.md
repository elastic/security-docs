---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-potential-privilege-escalation-via-local-kerberos-relay-over-ldap.html
---

# Potential Privilege Escalation via Local Kerberos Relay over LDAP [prebuilt-rule-8-2-1-potential-privilege-escalation-via-local-kerberos-relay-over-ldap]

Identifies a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account. This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
* [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.md)
* [https://github.com/cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation
* Credential Access

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2613]

```js
authentication where

 /* event 4624 need to be logged */
 event.action == "logged-in" and event.outcome == "success" and

 /* authenticate locally via relayed kerberos ticket */
 winlog.event_data.AuthenticationPackageName : "Kerberos" and winlog.logon.type == "Network" and
 source.ip == "127.0.0.1" and source.port > 0 and

 /* Impersonate Administrator user via S4U2Self service ticket */
 winlog.event_data.TargetUserSid : "S-1-5-21-*-500"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)



