---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-potential-ssh-brute-force-detected-on-privileged-account.html
---

# Potential SSH Brute Force Detected on Privileged Account [prebuilt-rule-8-7-1-potential-ssh-brute-force-detected-on-privileged-account]

Identifies multiple consecutive login failures targeting a root user account from the same source address and within a short time interval. Adversaries will often brute force login attempts on privileged accounts with a common or known password, in an attempt to gain privileged access to systems.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-system.auth-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Lateral Movement
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3817]

## Triage and analysis

## Investigating Potential SSH Brute Force Attack on Privileged Account

The rule identifies consecutive SSH login failures targeting a privileged (root) account from the same source IP address to the same target host indicating brute force login attempts.

### Possible investigation steps

- Investigate the login failure on privileged account(s).
- Investigate the source IP address of the failed ssh login attempt(s).
- Investigate other alerts associated with the user/host during the past 48 hours.
- Identify the source and the target computer and their roles in the IT environment.

## False positive analysis

- Authentication misconfiguration or obsolete credentials.
- Service account password expired.
- Infrastructure or availability issue.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4686]

```js
sequence by host.id, source.ip with maxspan=10s
  [authentication where event.action  in ("ssh_login", "user_login") and
   event.outcome == "failure" and source.ip != null and source.ip != "0.0.0.0" and
   source.ip != "::" and  user.name in ("*root*" , "*admin*")] with runs=3
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Password Guessing
    * ID: T1110.001
    * Reference URL: [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)

* Sub-technique:

    * Name: Password Spraying
    * ID: T1110.003
    * Reference URL: [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)



