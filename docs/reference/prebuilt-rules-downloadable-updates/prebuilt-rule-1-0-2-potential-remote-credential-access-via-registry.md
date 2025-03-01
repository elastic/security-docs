---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-remote-credential-access-via-registry.html
---

# Potential Remote Credential Access via Registry [prebuilt-rule-1-0-2-potential-remote-credential-access-via-registry]

Identifies remote access to the registry to potentially dump credential data from the Security Account Manager (SAM) registry hive in preparation for credential access and privileges elevation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement
* Credential Access

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1365]

## Triage and analysis

## Investigating Potential Remote Credential Access via Registry

Dumping registry hives is a common way to access credential information. Some hives store credential material,
such as the SAM hive, which stores locally cached credentials (SAM Secrets), and the SECURITY hive, which stores domain
cached credentials (LSA secrets). Dumping these hives in combination with the SYSTEM hive enables the attacker to
decrypt these secrets.

Attackers can use tools like secretsdump.py or CrackMapExec to dump the registry hives remotely, and use dumped
credentials to access other systems in the domain.

### Possible investigation steps

- Identify the target host role, involved account, and source host.
- Determine the privileges assigned to any compromised accounts.
- Investigate other alerts related to the involved user and source host in the last 48 hours.
- Scope potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target
host.

## False positive analysis

- False positives for this rule are unlikely. Any activity that triggered the alert and is not inherently malicious must
be monitored by the security team.

## Related rules

- Credential Acquisition via Registry Hive Dumping - a7e7bfa3-088e-4f13-b29e-3986e0e756b8

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Scope compromised credentials and disable the accounts.
- Reset the passwords of compromised accounts.
- Determine if other hosts were compromised.

## Config

This rule uses Elastic Endpoint file creation and System Integration events for correlation. Both data should be
collected from the host for this detection to work.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1594]

```js
sequence by host.id, user.id with maxspan=1m
 [authentication where
   event.outcome == "success" and
   winlog.logon.type == "Network" and not user.name == "ANONYMOUS LOGON" and
   not user.domain == "NT AUTHORITY" and source.ip != "127.0.0.1" and source.ip !="::1"]
 [file where event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : "S-1-5-21-*" and file.size >= 30000]
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

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)



