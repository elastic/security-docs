---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-potential-remote-desktop-tunneling-detected.html
---

# Potential Remote Desktop Tunneling Detected [prebuilt-rule-8-4-2-potential-remote-desktop-tunneling-detected]

Identifies potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*
* endgame-*

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
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3342]

## Triage and analysis

## Investigating Potential Remote Desktop Tunneling Detected

Protocol Tunneling is a mechanism that involves explicitly encapsulating a protocol within another for various use cases, ranging from providing an outer layer of encryption (similar to a VPN) to enabling traffic that network appliances would filter to reach their destination.

Attackers may tunnel Remote Desktop Protocol (RDP) traffic through other protocols like Secure Shell (SSH) to bypass network restrictions that block incoming RDP connections but may be more permissive to other protocols.

This rule looks for command lines involving the `3389` port, which RDP uses by default and options commonly associated with tools that perform tunneling.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account and system owners and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
- Examine network data to determine if the host communicated with external servers using the tunnel.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.
- Investigate the command line for the execution of programs that are unrelated to tunneling, like Remote Desktop clients.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Take the necessary actions to disable the tunneling, which can be a process kill, service deletion, registry key modification, etc. Inspect the host to learn which method was used and to determine a response for the case.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3980]

```js
process where event.type == "start" and
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



