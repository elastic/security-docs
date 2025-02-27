---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/statistical-model-detected-c2-beaconing-activity-with-high-confidence.html
---

# Statistical Model Detected C2 Beaconing Activity with High Confidence [statistical-model-detected-c2-beaconing-activity-with-high-confidence]

A statistical model has identified command-and-control (C2) beaconing activity with high confidence. Beaconing can help attackers maintain stealthy communication with their C2 servers, receive instructions and payloads, exfiltrate data and maintain persistence in a network.

**Rule type**: query

**Rule indices**:

* ml_beaconing.all

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-1h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
* [https://docs.elastic.co/en/integrations/beaconing](https://docs.elastic.co/en/integrations/beaconing)
* [https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic](https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic)

**Tags**:

* Domain: Network
* Use Case: C2 Beaconing Detection
* Tactic: Command and Control
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_953]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Statistical Model Detected C2 Beaconing Activity with High Confidence**

Statistical models analyze network traffic patterns to identify anomalies indicative of C2 beaconing, a tactic where attackers maintain covert communication with compromised systems. Adversaries exploit this to issue commands, exfiltrate data, and sustain network presence. The detection rule leverages a high beaconing score to flag potential threats, aiding analysts in pinpointing suspicious activities linked to C2 operations.

**Possible investigation steps**

* Review the network traffic logs to identify the source and destination IP addresses associated with the beaconing activity flagged by the beacon_stats.beaconing_score of 3.
* Correlate the identified IP addresses with known malicious IP databases or threat intelligence feeds to determine if they are associated with known C2 servers.
* Analyze the frequency and pattern of the beaconing activity to assess whether it aligns with typical C2 communication patterns, such as regular intervals or specific time frames.
* Investigate the domain names involved in the communication to check for any associations with malicious activities or suspicious registrations.
* Examine the payloads or data transferred during the flagged communication sessions to identify any potential exfiltration of sensitive information or receipt of malicious instructions.
* Cross-reference the involved systems with internal asset inventories to determine if they are critical assets or have been previously flagged for suspicious activities.
* Consult with the incident response team to decide on containment or remediation actions if the investigation confirms malicious C2 activity.

**False positive analysis**

* Regularly scheduled software updates or patch management systems may generate network traffic patterns similar to C2 beaconing. Users can create exceptions for known update servers to reduce false positives.
* Automated backup systems that frequently communicate with cloud storage services might be flagged. Identifying and excluding these backup services from the analysis can help mitigate this issue.
* Network monitoring tools that periodically check connectivity or system health can mimic beaconing activity. Whitelisting these monitoring tools can prevent them from being incorrectly flagged.
* Internal applications that use polling mechanisms to check for updates or status changes may trigger alerts. Documenting and excluding these applications from the rule can minimize false positives.
* Frequent communication with trusted third-party services, such as content delivery networks, may appear as beaconing. Establishing a list of trusted domains and excluding them from the analysis can help manage this.

**Response and remediation**

* Isolate the affected systems from the network to prevent further communication with the C2 server and contain the threat.
* Conduct a thorough analysis of the network traffic logs to identify any additional compromised systems or lateral movement within the network.
* Remove any malicious software or scripts identified on the compromised systems, ensuring all traces of the C2 communication channels are eradicated.
* Apply security patches and updates to all affected systems to close any vulnerabilities exploited by the attackers.
* Change all credentials and authentication tokens associated with the compromised systems to prevent unauthorized access.
* Monitor the network for any signs of re-infection or continued C2 activity, using enhanced detection rules and updated threat intelligence.
* Escalate the incident to the appropriate internal security team or external cybersecurity experts for further investigation and to assess the potential impact on the organization.


## Setup [_setup_604]

**Setup**

The rule requires the Network Beaconing Identification integration assets to be installed, as well as network logs collected by the Elastic Defend or Network Packet Capture integrations.

**Network Beaconing Identification Setup**

The Network Beaconing Identification integration consists of a statistical framework to identify C2 beaconing activity in network logs.

**Prerequisite Requirements:**

* Fleet is required for Network Beaconing Identification.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Network events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) or [Network Packet Capture](https://docs.elastic.co/integrations/network_traffic) integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To add the Network Packet Capture integration to an Elastic Agent policy, refer to [this](docs-content://reference/ingestion-tools/fleet/add-integration-to-policy.md) guide.

**The following steps should be executed to install assets associated with the Network Beaconing Identification integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Network Beaconing Identification and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.


## Rule query [_rule_query_1001]

```js
beacon_stats.beaconing_score: 3
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Web Service
    * ID: T1102
    * Reference URL: [https://attack.mitre.org/techniques/T1102/](https://attack.mitre.org/techniques/T1102/)

* Sub-technique:

    * Name: Bidirectional Communication
    * ID: T1102.002
    * Reference URL: [https://attack.mitre.org/techniques/T1102/002/](https://attack.mitre.org/techniques/T1102/002/)



