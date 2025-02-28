---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-machine-learning-detected-a-dns-request-with-a-high-dga-probability-score.html
---

# Machine Learning Detected a DNS Request With a High DGA Probability Score [prebuilt-rule-8-17-4-machine-learning-detected-a-dns-request-with-a-high-dga-probability-score]

A supervised machine learning model has identified a DNS question name with a high probability of sourcing from a Domain Generation Algorithm (DGA), which could indicate command and control network activity.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*
* logs-network_traffic.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
* [https://docs.elastic.co/en/integrations/dga](https://docs.elastic.co/en/integrations/dga)
* [https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration](https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration)

**Tags**:

* Domain: Network
* Domain: Endpoint
* Data Source: Elastic Defend
* Use Case: Domain Generation Algorithm Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Command and Control
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4146]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Machine Learning Detected a DNS Request With a High DGA Probability Score**

Machine learning models analyze DNS requests to identify patterns indicative of Domain Generation Algorithms (DGAs), often used by attackers to establish command and control channels. These algorithms generate numerous domain names, making detection challenging. The detection rule leverages a model to flag DNS queries with high DGA probability, aiding in identifying potential malicious activity.

**Possible investigation steps**

* Review the DNS query logs to identify the specific domain name associated with the high DGA probability score and gather additional context about the request, such as the timestamp and the source IP address.
* Cross-reference the identified domain name with threat intelligence databases to determine if it is a known malicious domain or associated with any known threat actors or campaigns.
* Investigate the source IP address to determine if it belongs to a legitimate user or system within the network, and check for any unusual or suspicious activity associated with this IP address.
* Analyze network traffic logs to identify any additional communication attempts to the flagged domain or other suspicious domains, which may indicate further command and control activity.
* Check endpoint security logs for any signs of compromise or suspicious behavior on the device that initiated the DNS request, such as unexpected processes or connections.
* Consider isolating the affected system from the network if there is strong evidence of compromise, to prevent further potential malicious activity while conducting a deeper forensic analysis.

**False positive analysis**

* Legitimate software updates or services may use domain generation techniques for load balancing or redundancy, leading to false positives. Users can create exceptions for known update services or trusted software to reduce these alerts.
* Content delivery networks (CDNs) often use dynamically generated domains to optimize content delivery, which might be flagged. Identifying and whitelisting these CDN domains can help minimize unnecessary alerts.
* Some security tools and applications use DGA-like patterns for legitimate purposes, such as generating unique identifiers. Users should verify the source and purpose of these requests and consider excluding them if they are confirmed to be non-threatening.
* Internal testing environments or development tools might generate domains that resemble DGA activity. Users can exclude these environments from monitoring or adjust the rule to ignore specific internal IP ranges or domain patterns.

**Response and remediation**

* Isolate the affected system from the network to prevent further potential command and control communication.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious software.
* Review and block the identified suspicious domain names at the network perimeter to prevent any further communication attempts.
* Analyze network traffic logs to identify any other systems that may have communicated with the flagged domains and apply similar containment measures.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement additional monitoring on the affected system and network segment to detect any signs of persistence or further malicious activity.
* Update and reinforce endpoint protection measures, ensuring all systems have the latest security patches and configurations to prevent similar threats in the future.


## Setup [_setup_1016]

**Setup**

The rule requires the Domain Generation Algorithm (DGA) Detection integration assets to be installed, as well as DNS events collected by integrations such as Elastic Defend, Network Packet Capture, or Packetbeat.

**DGA Detection Setup**

The DGA Detection integration consists of an ML-based framework to detect DGA activity in DNS events.

**Prerequisite Requirements:**

* Fleet is required for DGA Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* DNS events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint), [Network Packet Capture](https://docs.elastic.co/integrations/network_traffic) integration, or [Packetbeat](beats://reference/packetbeat/packetbeat-overview.md).
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To add the Network Packet Capture integration to an Elastic Agent policy, refer to [this](docs-content://reference/ingestion-tools/fleet/add-integration-to-policy.md) guide.
* To set up and run Packetbeat, follow [this](beats://reference/packetbeat/setting-up-running.md) guide.

**The following steps should be executed to install assets associated with the DGA Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Domain Generation Algorithm Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Configure the ingest pipeline***.


## Rule query [_rule_query_5155]

```js
ml_is_dga.malicious_probability > 0.98
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Dynamic Resolution
    * ID: T1568
    * Reference URL: [https://attack.mitre.org/techniques/T1568/](https://attack.mitre.org/techniques/T1568/)

* Sub-technique:

    * Name: Domain Generation Algorithms
    * ID: T1568.002
    * Reference URL: [https://attack.mitre.org/techniques/T1568/002/](https://attack.mitre.org/techniques/T1568/002/)



