---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-spike-in-successful-logon-events-from-a-source-ip.html
---

# Spike in Successful Logon Events from a Source IP [prebuilt-rule-8-6-1-spike-in-successful-logon-events-from-a-source-ip]

A machine learning job found an unusually large spike in successful authentication events from a particular source IP address. This can be due to password spraying, user enumeration or brute force activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Elastic
* Authentication
* Threat Detection
* ML
* Credential Access
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3751]

## Triage and analysis

## Investigating Spike in Successful Logon Events from a Source IP

This rule uses a machine learning job to detect a substantial spike in successful authentication events. This could indicate post-exploitation activities that aim to test which hosts, services, and other resources the attacker can access with the compromised credentials.

### Possible investigation steps

- Identify the specifics of the involved assets, such as role, criticality, and associated users.
- Check if the authentication comes from different sources.
- Use the historical data available to determine if the same behavior happened in the past.
- Investigate other alerts associated with the involved users during the past 48 hours.
- Check whether the involved credentials are used in automation or scheduled tasks.
- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.

## False positive analysis

- Understand the context of the authentications by contacting the asset owners. If this activity is related to a new business process or newly implemented (approved) technology, consider adding exceptions — preferably with a combination of user and source conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



