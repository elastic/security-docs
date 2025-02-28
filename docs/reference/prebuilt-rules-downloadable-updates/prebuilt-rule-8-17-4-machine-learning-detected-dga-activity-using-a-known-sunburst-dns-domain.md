---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-machine-learning-detected-dga-activity-using-a-known-sunburst-dns-domain.html
---

# Machine Learning Detected DGA activity using a known SUNBURST DNS domain [prebuilt-rule-8-17-4-machine-learning-detected-dga-activity-using-a-known-sunburst-dns-domain]

A supervised machine learning model has identified a DNS question name that used by the SUNBURST malware and is predicted to be the result of a Domain Generation Algorithm.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*
* logs-network_traffic.*

**Severity**: critical

**Risk score**: 99

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

## Investigation guide [_investigation_guide_4144]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Machine Learning Detected DGA activity using a known SUNBURST DNS domain**

Domain Generation Algorithms (DGAs) are used by adversaries to dynamically generate domain names for command and control (C2) communication, making it difficult to block malicious domains. The SUNBURST malware utilized such techniques. The detection rule leverages machine learning to identify DNS queries linked to these generated domains, specifically targeting those associated with SUNBURST, by analyzing patterns and predicting malicious activity, thus aiding in early threat detection and mitigation.

**Possible investigation steps**

* Review the DNS logs to identify the source IP address associated with the DNS query for avsvmcloud.com to determine the affected host within the network.
* Check historical DNS query logs for the identified host to see if there are additional queries to other suspicious or known malicious domains, indicating further compromise.
* Investigate the network traffic from the identified host around the time of the alert to detect any unusual patterns or connections to external IP addresses that may suggest command and control activity.
* Examine endpoint security logs and alerts for the affected host to identify any signs of SUNBURST malware or other related malicious activity.
* Correlate the alert with other security events in the environment to determine if there are any related incidents or patterns that could indicate a broader attack campaign.
* Assess the risk and impact of the detected activity on the organization and determine if immediate containment or remediation actions are necessary.

**False positive analysis**

* Legitimate software updates or network services may occasionally use domain generation algorithms for load balancing or redundancy, leading to false positives. Users should monitor and whitelist these known benign services.
* Internal testing environments or security tools that simulate DGA behavior for research or training purposes might trigger alerts. Exclude these environments by adding them to an exception list.
* Some cloud services might use dynamic DNS techniques that resemble DGA patterns. Identify and document these services, then configure exceptions to prevent unnecessary alerts.
* Frequent legitimate access to avsvmcloud.com by security researchers or analysts could be misclassified. Ensure these activities are logged and reviewed, and create exceptions for known research IPs or user accounts.
* Regularly review and update the exception list to ensure it reflects current network behavior and does not inadvertently allow new threats.

**Response and remediation**

* Isolate the affected systems immediately to prevent further communication with the malicious domain avsvmcloud.com and halt potential data exfiltration or lateral movement.
* Conduct a thorough scan of the isolated systems using updated antivirus and anti-malware tools to identify and remove any SUNBURST malware or related malicious files.
* Review and block any outbound traffic to the domain avsvmcloud.com at the network perimeter to prevent future connections from other potentially compromised systems.
* Analyze network logs and DNS query records to identify any other systems that may have communicated with the domain, and apply the same isolation and scanning procedures to those systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the compromise.
* Implement enhanced monitoring and alerting for any DNS queries or network traffic patterns indicative of DGA activity, particularly those resembling SUNBURST characteristics, to detect and respond to similar threats promptly.
* Review and update incident response and recovery plans to incorporate lessons learned from this incident, ensuring faster and more effective responses to future threats.


## Setup [_setup_1014]

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


## Rule query [_rule_query_5154]

```js
ml_is_dga.malicious_prediction:1 and dns.question.registered_domain:avsvmcloud.com
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



