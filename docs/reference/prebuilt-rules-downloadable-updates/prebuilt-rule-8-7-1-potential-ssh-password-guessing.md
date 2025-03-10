---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-potential-ssh-password-guessing.html
---

# Potential SSH Password Guessing [prebuilt-rule-8-7-1-potential-ssh-password-guessing]

Identifies multiple SSH login failures followed by a successful one from the same source address. Adversaries can attempt to login into multiple users with a common or known password to gain access to accounts.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-system.auth-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3815]

## Triage and analysis

## Investigating Potential SSH Password Guessing Attack

The rule identifies consecutive SSH login failures followed by a successful login from the same source IP address to the same target host indicating a successful attempt of brute force password guessing.

### Possible investigation steps

- Investigate the login failure user name(s).
- Investigate the source IP address of the failed ssh login attempt(s).
- Investigate other alerts associated with the user/host during the past 48 hours.
- Identify the source and the target computer and their roles in the IT environment.

## False positive analysis

- Authentication misconfiguration or obsolete credentials.
- Service account password expired.
- Infrastructure or availability issue.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Ensure active session(s) on the host(s) are terminated as the attacker could have gained initial access to the system(s).
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4683]

```js
sequence by host.id, source.ip, user.name with maxspan=3s
  [authentication where event.action  in ("ssh_login", "user_login") and
   event.outcome == "failure" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ] with runs=2

  [authentication where event.action  in ("ssh_login", "user_login") and
   event.outcome == "success" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ]
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



