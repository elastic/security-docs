---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-hosts-file-modified.html
---

# Hosts File Modified [prebuilt-rule-8-3-2-hosts-file-modified]

The hosts file on endpoints is used to control manual IP address to hostname resolutions. The hosts file is the first point of lookup for DNS hostname resolution so if adversaries can modify the endpoint hosts file, they can route traffic to malicious infrastructure. This rule detects modifications to the hosts file on Microsoft Windows, Linux (Ubuntu or RHEL) and macOS systems.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/beats/docs/reference/ingestion-tools/beats-auditbeat/auditbeat-reference-yml.md](beats://reference/auditbeat/auditbeat-reference-yml.md)

**Tags**:

* Elastic
* Host
* Linux
* Windows
* macOS
* Threat Detection
* Impact

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2356]

## Triage and analysis

## Investigating Hosts File Modified

Operating systems use the hosts file to map a connection between an IP address and domain names before going to domain
name servers. Attackers can abuse this mechanism to route traffic to malicious infrastructure or disrupt security that
depends on server communications. For example, Russian threat actors modified this file on a domain controller to
redirect Duo MFA calls to localhost instead of the Duo server, which prevented the MFA service from contacting its
server to validate MFA login. This effectively disabled MFA for active domain accounts because the default policy of Duo
for Windows is to "Fail open" if the MFA server is unreachable. This can happen in any MFA implementation and is not
exclusive to Duo. Find more details in this [CISA Alert](https://www.cisa.gov/uscert/ncas/alerts/aa22-074a).

This rule identifies modifications in the hosts file across multiple operating systems using process creation events for
Linux and file events in Windows and macOS.

### Possible investigation steps

- Identify the specifics of the involved assets, such as role, criticality, and associated users.
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the changes to the hosts file by comparing it against file backups, volume shadow copies, and other restoration
mechanisms.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity
and the configuration was justified.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Consider isolating the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Review the privileges of the administrator account that performed the action.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2727]

```js
any where

  /* file events for creation; file change events are not captured by some of the included sources for linux and so may
     miss this, which is the purpose of the process + command line args logic below */
  (
   event.category == "file" and event.type in ("change", "creation") and
     file.path : ("/private/etc/hosts", "/etc/hosts", "?:\\Windows\\System32\\drivers\\etc\\hosts")
  )
  or

  /* process events for change targeting linux only */
  (
   event.category == "process" and event.type in ("start") and
     process.name in ("nano", "vim", "vi", "emacs", "echo", "sed") and
     process.args : ("/etc/hosts")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Manipulation
    * ID: T1565
    * Reference URL: [https://attack.mitre.org/techniques/T1565/](https://attack.mitre.org/techniques/T1565/)

* Sub-technique:

    * Name: Stored Data Manipulation
    * ID: T1565.001
    * Reference URL: [https://attack.mitre.org/techniques/T1565/001/](https://attack.mitre.org/techniques/T1565/001/)



