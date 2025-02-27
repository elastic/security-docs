---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-shadow-credentials-added-to-ad-object.html
---

# Potential Shadow Credentials added to AD Object [prebuilt-rule-1-0-2-potential-shadow-credentials-added-to-ad-object]

Identifies the modification of the msDS-KeyCredentialLink attribute in an Active Directory Computer or User Object. Attackers can abuse control over the object and create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target user or computer object.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [https://github.com/OTRF/Set-AuditRule](https://github.com/OTRF/Set-AuditRule)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Active Directory

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1367]

## Config

The 'Audit Directory Service Changes' logging policy must be configured for (Success, Failure).
Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```

The above policy does not cover User objects, so we need to set up an AuditRule using https://github.com/OTRF/Set-AuditRule.
As this specifies the msDS-KeyCredentialLink Attribute GUID, it is expected to be low noise.

```
Set-AuditRule -AdObjectPath 'AD:\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID 5b47d60f-6090-40b2-9f37-2a4de88f3063 -AuditFlags Success
```

## Rule query [_rule_query_1596]

```js
event.action:"Directory Service Changes" and event.code:"5136" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



