---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/halfbaked-command-and-control-beacon.html
---

# Halfbaked Command and Control Beacon [halfbaked-command-and-control-beacon]

Halfbaked is a malware family used to establish persistence in a contested network. This rule detects a network activity algorithm leveraged by Halfbaked implant beacons for command and control.

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

* [https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.md)
* [https://attack.mitre.org/software/S0151/](https://attack.mitre.org/software/S0151/)

**Tags**:

* Use Case: Threat Detection
* Tactic: Command and Control
* Domain: Endpoint
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_405]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Halfbaked Command and Control Beacon**

Halfbaked malware exploits common network protocols to maintain persistence and facilitate command and control (C2) operations within compromised networks. Adversaries leverage HTTP and TLS protocols to disguise malicious traffic as legitimate, often targeting specific ports like 53, 80, 8080, and 443. The detection rule identifies suspicious network patterns, such as unusual URL structures and specific transport protocols, to flag potential C2 beaconing activities.

**Possible investigation steps**

* Review the network traffic logs to identify any connections to IP addresses matching the pattern specified in the query (e.g., http://[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/cd) and determine if these IPs are known or suspicious.
* Analyze the destination ports (53, 80, 8080, 443) used in the flagged traffic to assess if they align with typical usage patterns for the affected systems or if they indicate potential misuse.
* Examine the HTTP and TLS traffic details to identify any unusual URL structures or anomalies in the network.protocol field that could suggest malicious activity.
* Correlate the detected network activity with endpoint logs to identify any associated processes or applications that may have initiated the suspicious traffic.
* Investigate any related alerts or historical data for patterns of similar activity, which could indicate a persistent threat or ongoing compromise within the network.

**False positive analysis**

* Legitimate software updates or patch management systems may use similar URL structures and ports, leading to false positives. Users can create exceptions for known update servers by whitelisting their IP addresses or domain names.
* Internal web applications or services that use non-standard ports like 8080 for HTTP traffic might trigger the rule. Identify these applications and exclude their traffic from the rule by specifying their IP addresses or domain names.
* Network monitoring tools or security appliances that perform regular scans or health checks over HTTP or TLS might mimic the detected patterns. Exclude these tools by adding their IP addresses to an exception list.
* Content delivery networks (CDNs) often use IP-based URLs for load balancing and might be mistaken for malicious activity. Verify the legitimacy of the CDN traffic and exclude it by whitelisting the associated IP ranges.
* Automated scripts or bots within the network that access external resources using IP-based URLs could trigger alerts. Review these scripts and, if deemed safe, exclude their traffic by specifying their source IP addresses.

**Response and remediation**

* Isolate the affected systems from the network immediately to prevent further communication with the command and control server.
* Conduct a thorough scan of the isolated systems using updated antivirus and anti-malware tools to identify and remove the Halfbaked malware.
* Analyze network traffic logs to identify other potentially compromised systems by looking for similar suspicious network patterns and URL structures.
* Block the identified malicious IP addresses and domains at the network perimeter to prevent further communication attempts.
* Apply security patches and updates to all systems and applications to close vulnerabilities exploited by the malware.
* Restore affected systems from clean backups, ensuring that the backups are free from any signs of compromise.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the scope of the breach.

**Threat intel**

This activity has been observed in FIN7 campaigns.


## Rule query [_rule_query_440]

```js
(event.dataset: (network_traffic.tls OR network_traffic.http) OR
  (event.category: (network OR network_traffic) AND network.protocol: http)) AND
  network.transport:tcp AND url.full:/http:\/\/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/cd/ AND
  destination.port:(53 OR 80 OR 8080 OR 443)
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



