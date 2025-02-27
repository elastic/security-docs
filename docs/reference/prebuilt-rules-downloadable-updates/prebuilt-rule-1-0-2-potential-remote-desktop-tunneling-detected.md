---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-remote-desktop-tunneling-detected.html
---

# Potential Remote Desktop Tunneling Detected [prebuilt-rule-1-0-2-potential-remote-desktop-tunneling-detected]

Identifies potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.netspi.com/how-to-access-rdp-over-a-reverse-ssh-tunnel/](https://blog.netspi.com/how-to-access-rdp-over-a-reverse-ssh-tunnel/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1501]

## Triage and analysis

## Investigating Potential Remote Desktop Tunneling Detected

Protocol Tunneling is a mechanism that involves explicitly encapsulating a protocol within another for various use cases,
ranging from providing an outer layer of encryption (similar to a VPN) to enabling traffic that network appliances would
filter to reach their destination.

Attackers may tunnel Remote Desktop Protocol (RDP) traffic through other protocols like Secure Shell (SSH) to bypass network restrictions that block incoming RDP
connections but may be more permissive to other protocols.

This rule looks for command lines involving the `3389` port, which RDP uses by default and options commonly associated
with tools that perform tunneling.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Determine if the activity is unique by validating if other machines in the organization have similar entries.
- Examine network data to determine if the host communicated with external servers using the tunnel.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.
- Investigate the command line for the execution of programs that are unrelated to tunneling, like Remote Desktop clients.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Disable the involved accounts, or restrict their ability to log on remotely.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Take actions to disable the tunneling.
- Investigate the initial attack vector.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1736]

```js
process where event.type in ("start", "process_started") and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



