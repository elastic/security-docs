---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-port-forwarding-rule-addition.html
---

# Port Forwarding Rule Addition [prebuilt-rule-1-0-2-port-forwarding-rule-addition]

Identifies the creation of a new port forwarding rule. An adversary may abuse this technique to bypass network segmentation restrictions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1500]

## Triage and analysis

## Investigating Port Forwarding Rule Addition

Network port forwarding is a mechanism to redirect incoming TCP connections (IPv4 or IPv6) from the local TCP port to
any other port number, or even to a port on a remote computer.

Attackers may configure port forwarding rules to bypass network segmentation restrictions, using the host as a jump box
to access previously unreachable systems.

This rule monitors the modifications to the `HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\` subkeys.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check for similar behavior in other hosts on the environment.
- Identify the target host IP address, verify if connections were made from the host where the modification occurred,
and check what credentials were used to perform it.
  - Investigate suspicious login activity, such as unauthorized access and logins from outside working hours and unusual locations.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the Administrator is aware of the activity
and there are justifications for this configuration.
- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination
of user and command line conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Delete the port forwarding rule.
- Isolate the involved host to prevent further post-compromise behavior.
- If potential malware or credential compromise activities were discovered during the alert triage, activate the respective
incident response plan.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1735]

```js
registry where registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*"
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



