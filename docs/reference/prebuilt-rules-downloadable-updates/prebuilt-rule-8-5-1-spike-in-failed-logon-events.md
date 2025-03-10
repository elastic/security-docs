---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-spike-in-failed-logon-events.html
---

# Spike in Failed Logon Events [prebuilt-rule-8-5-1-spike-in-failed-logon-events]

A machine learning job found an unusually large spike in authentication failure events. This can be due to password spraying, user enumeration or brute force activity and may be a precursor to account takeover or credentialed access.

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

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3672]

## Triage and analysis

## Investigating Spike in Failed Logon Events

This rule uses a machine learning job to detect a substantial spike in failed authentication events. This could indicate attempts to enumerate users, password spraying, brute force, etc.

### Possible investigation steps

- Identify the users involved and if the activity targets a specific user or a set of users.
- Check if the authentication comes from different sources.
- Investigate if the host where the failed authentication events occur is exposed to the internet.
  - If the host is exposed to the internet, and the source of these attempts is external, the activity can be related to bot activity and possibly not directed at your organization.
  - If the host is not exposed to the internet, investigate the hosts where the authentication attempts are coming from, as this can indicate that they are compromised and the attacker is trying to move laterally.
- Investigate other alerts associated with the involved users and hosts during the past 48 hours.
- Check whether the involved credentials are used in automation or scheduled tasks.
- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.
- Investigate whether there are successful authentication events from the involved sources. This could indicate a successful brute force or password spraying attack.

## False positive analysis

- If the account is used in automation tasks, it is possible that they are using expired credentials, causing a spike in authentication failures.
- Authentication failures can be related to permission issues.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Assess whether the asset should be exposed to the internet, and take action to reduce your attack surface.
  - If the asset needs to be exposed to the internet, restrict access to remote login services to specific IPs.
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



