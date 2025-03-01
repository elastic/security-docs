---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-kerberos-traffic-from-unusual-process.html
---

# Kerberos Traffic from Unusual Process [prebuilt-rule-1-0-2-kerberos-traffic-from-unusual-process]

Identifies network connections to the standard Kerberos port from an unusual process. On Windows, the only process that normally performs Kerberos traffic from a domain joined host is lsass.exe.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1514]

## Triage and analysis

## Investigating Kerberos Traffic from Unusual Process

Kerberos is the default authentication protocol in Active Directory, designed to provide strong authentication for
client/server applications by using secret-key cryptography.

Domain-joined hosts usually perform Kerberos traffic using the `lsass.exe` process. This rule detects the occurrence of
traffic on the Kerberos port (88) by processes other than `lsass.exe` to detect the unusual request and usage of
Kerberos tickets.

### Possible investigation steps

- Investigate script execution chain (parent process tree).
- Investigate other alerts related to the host and user in the last 48 hours.
- Check if the Destination IP is related to a Domain Controller.
- Review event ID 4769 for suspicious ticket requests.

## False positive analysis

- This rule uses a Kerberos-related port but does not identify the protocol used on that port. HTTP traffic on a
non-standard port or destination IP address unrelated to Domain controllers can create false positives.
- Exceptions can be added for noisy/frequent connections.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Scope possible compromised credentials based on ticket requests.
- Isolate the involved host to prevent further post-compromise behavior.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1750]

```js
network where event.type == "start" and network.direction : ("outgoing", "egress") and
 destination.port == 88 and source.port >= 49152 and
 process.executable != "C:\\Windows\\System32\\lsass.exe" and destination.address !="127.0.0.1" and destination.address !="::1" and
 /* insert false positives here */
 not process.name in ("swi_fc.exe", "fsIPcam.exe", "IPCamera.exe", "MicrosoftEdgeCP.exe", "MicrosoftEdge.exe", "iexplore.exe", "chrome.exe", "msedge.exe", "opera.exe", "firefox.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)



