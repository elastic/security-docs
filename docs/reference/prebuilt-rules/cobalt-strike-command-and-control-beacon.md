---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/cobalt-strike-command-and-control-beacon.html
---

# Cobalt Strike Command and Control Beacon [cobalt-strike-command-and-control-beacon]

Cobalt Strike is a threat emulation platform commonly modified and used by adversaries to conduct network attack and exploitation campaigns. This rule detects a network activity algorithm leveraged by Cobalt Strike implant beacons for command and control.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.morphisec.com/fin7-attacks-restaurant-industry](https://blog.morphisec.com/fin7-attacks-restaurant-industry)
* [https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.md)
* [https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack](https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack)

**Tags**:

* Use Case: Threat Detection
* Tactic: Command and Control
* Domain: Endpoint
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_220]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Cobalt Strike Command and Control Beacon**

Cobalt Strike is a penetration testing tool often repurposed by attackers for malicious activities, particularly for establishing command and control (C2) channels. Adversaries exploit its beaconing feature to communicate with compromised systems using common protocols like HTTP or TLS. The detection rule identifies suspicious network patterns, such as specific domain naming conventions, indicative of Cobalt Strike’s C2 activity, helping analysts pinpoint potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific domain that triggered the rule, focusing on the pattern `[a-z]{3}.stage.[0-9]{8}\..*` to determine if it matches known malicious domains.
* Analyze the network traffic logs associated with the alert, specifically looking at events categorized under network or network_traffic with types tls or http, to gather more context about the communication.
* Investigate the source IP address and destination domain involved in the alert to determine if they have been associated with previous malicious activities or are listed in threat intelligence databases.
* Examine the timeline of the network activity to identify any patterns or anomalies that could indicate a larger campaign or coordinated attack.
* Check for any related alerts or incidents in the security information and event management (SIEM) system that might provide additional context or indicate a broader compromise.
* Assess the affected endpoint for any signs of compromise, such as unusual processes or connections, to determine if further containment or remediation actions are necessary.

**False positive analysis**

* Legitimate software updates or patch management systems may use similar domain naming conventions. Review and whitelist known update servers to prevent false alerts.
* Internal development or testing environments might mimic Cobalt Strike’s domain patterns for legitimate purposes. Identify and exclude these environments from the rule.
* Automated scripts or tools that generate network traffic with similar domain structures can trigger false positives. Monitor and document these tools, then create exceptions for their activity.
* Some content delivery networks (CDNs) might use domain patterns that match the rule’s criteria. Verify and exclude trusted CDNs to reduce unnecessary alerts.
* Regularly review and update the list of exceptions to ensure that only verified non-threatening behaviors are excluded, maintaining the rule’s effectiveness.

**Response and remediation**

* Isolate the affected systems immediately to prevent further communication with the Cobalt Strike C2 server. This can be done by disconnecting the network or using network segmentation techniques.
* Conduct a thorough forensic analysis of the compromised systems to identify the extent of the breach and any additional payloads or backdoors that may have been installed.
* Remove any identified Cobalt Strike beacons or related malware from the affected systems using updated antivirus or endpoint detection and response (EDR) tools.
* Change all credentials and access tokens that may have been exposed or used on the compromised systems to prevent unauthorized access.
* Monitor network traffic for any signs of re-infection or communication attempts with known Cobalt Strike C2 domains, using updated threat intelligence feeds.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data have been compromised.
* Implement network-level controls, such as blocking known malicious domains and IP addresses associated with Cobalt Strike, to prevent future attacks.

**Threat intel**

This activity has been observed in FIN7 campaigns.


## Rule query [_rule_query_228]

```js
((event.category: (network OR network_traffic) AND type: (tls OR http))
    OR event.dataset: (network_traffic.tls OR network_traffic.http)
) AND destination.domain:/[a-z]{3}.stage.[0-9]{8}\..*/
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

* Technique:

    * Name: Dynamic Resolution
    * ID: T1568
    * Reference URL: [https://attack.mitre.org/techniques/T1568/](https://attack.mitre.org/techniques/T1568/)

* Sub-technique:

    * Name: Domain Generation Algorithms
    * ID: T1568.002
    * Reference URL: [https://attack.mitre.org/techniques/T1568/002/](https://attack.mitre.org/techniques/T1568/002/)



