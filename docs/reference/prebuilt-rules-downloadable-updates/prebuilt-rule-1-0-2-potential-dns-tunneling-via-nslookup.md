---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-dns-tunneling-via-nslookup.html
---

# Potential DNS Tunneling via NsLookup [prebuilt-rule-1-0-2-potential-dns-tunneling-via-nslookup]

This rule identifies a large number (15) of `nslookup.exe` executions with an explicit query type from the same host. This may indicate command and control activity utilizing the DNS protocol.

**Rule type**: threshold

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

* [https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1498]

## Triage and analysis

## Investigating Potential DNS Tunneling via NsLookup

Attackers can abuse existing network rules that allow DNS communication with external resources to use the protocol as
their command and control and/or exfiltration channel.

DNS queries can be used to infiltrate data such as commands to be run, malicious files, etc., and also for exfiltration,
since queries can be used to send data to the attacker-controlled DNS server. This process is commonly known as DNS tunneling.

More information on how tunneling works and how it can be abused can be found on
[Palo Alto Unit42 Research](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors).

### Possible investigation steps

- Investigate the script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Inspect the DNS query and identify the information sent.
- Extract this communication's indicators of compromise (IoCs) and use traffic logs to search for other potentially compromised hosts.

## False positive analysis

- This mechanism can be used legitimately. If the parent process is trusted and the data sent is not sensitive nor
command and control related, this alert can be closed.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Immediately block the IoCs identified on the triage.
- Implement any temporary network rules, procedures, and segmentation required to contain the attack.
- Capture forensic images to preserve evidence.
- Reset the password for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Update firewall rules to be more restrictive.
- Reimage affected systems.

## Rule query [_rule_query_1732]

```js
event.category:process and event.type:start and process.name:nslookup.exe and process.args:(-querytype=* or -qt=* or -q=* or -type=*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: DNS
    * ID: T1071.004
    * Reference URL: [https://attack.mitre.org/techniques/T1071/004/](https://attack.mitre.org/techniques/T1071/004/)



