---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-dga-activity.html
---

# Potential DGA Activity [potential-dga-activity]

A population analysis machine learning job detected potential DGA (domain generation algorithm) activity. Such activity is often used by malware command and control (C2) channels. This machine learning job looks for a source IP address making DNS requests that have an aggregate high probability of being DGA activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
* [https://docs.elastic.co/en/integrations/dga](https://docs.elastic.co/en/integrations/dga)
* [https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration](https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration)

**Tags**:

* Use Case: Domain Generation Algorithm Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Command and Control
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_663]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential DGA Activity**

Domain Generation Algorithms (DGAs) are used by malware to dynamically generate domain names for command and control (C2) communication, making it difficult to block malicious domains. Adversaries exploit this by frequently changing domains to evade detection. The *Potential DGA Activity* detection rule leverages machine learning to analyze DNS requests from source IPs, identifying patterns indicative of DGA usage, thus flagging potential threats for further investigation.

**Possible investigation steps**

* Review the source IP address identified in the alert to determine if it belongs to a known or trusted entity within the organization.
* Analyze the DNS request patterns from the source IP to identify any unusual or suspicious domain names that may indicate DGA activity.
* Cross-reference the flagged domains with threat intelligence feeds to check for known malicious domains or patterns associated with DGAs.
* Investigate the network traffic associated with the source IP to identify any additional indicators of compromise or communication with known malicious IPs.
* Check for any recent changes or anomalies in the system or network configurations that could explain the detected activity.
* Assess the risk score and severity in the context of the organization’s environment to prioritize the investigation and response efforts.

**False positive analysis**

* Legitimate software updates or cloud services may generate high volumes of DNS requests that resemble DGA patterns. Users can create exceptions for known update servers or cloud service domains to reduce false positives.
* Content delivery networks (CDNs) often use dynamically generated subdomains for load balancing and distribution, which can trigger DGA alerts. Identifying and excluding these CDN domains from analysis can help mitigate false positives.
* Large organizations with complex internal networks might have internal applications that generate DNS requests similar to DGA activity. Conducting a thorough review of internal DNS traffic and whitelisting known internal domains can prevent these false positives.
* Some security tools or network appliances may perform DNS lookups as part of their normal operation, which could be misclassified as DGA activity. Identifying these tools and excluding their IP addresses from the analysis can help manage false positives.

**Response and remediation**

* Isolate the affected systems: Immediately disconnect any systems identified as making suspicious DNS requests from the network to prevent further communication with potential C2 servers.
* Block identified domains: Use firewall and DNS filtering solutions to block the domains flagged by the detection rule, preventing any further communication attempts.
* Conduct a thorough system scan: Use updated antivirus and anti-malware tools to scan the isolated systems for any signs of infection or malicious software.
* Analyze network traffic: Review network logs to identify any additional suspicious activity or other systems that may be affected, focusing on unusual DNS requests and connections.
* Patch and update systems: Ensure all systems, especially those identified in the alert, are fully patched and updated to mitigate vulnerabilities that could be exploited by malware.
* Restore from backups: If malware is confirmed, restore affected systems from clean backups to ensure no remnants of the infection remain.
* Escalate to incident response team: If the threat is confirmed and widespread, escalate the incident to the organization’s incident response team for further investigation and coordinated response efforts.


## Setup [_setup_422]

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
* For this rule to work, complete the instructions through ***Add preconfigured anomaly detection jobs***.

**Anomaly Detection Setup**

Before you can enable this rule, you’ll need to enable the corresponding Anomaly Detection job. - Go to the Kibana homepage. Under Analytics, click Machine Learning. - Under Anomaly Detection, click Jobs, and then click "Create job". Select the Data View containing your enriched DNS events. For example, this would be `logs-endpoint.events.*` if you used Elastic Defend to collect events, or `logs-network_traffic.*` if you used Network Packet Capture. - If the selected Data View contains events that match the query in [this](https://github.com/elastic/integrations/blob/main/packages/dga/kibana/ml_module/dga-ml.json) configuration file, you will see a card for DGA under "Use preconfigured jobs". - Keep the default settings and click "Create jobs" to start the anomaly detection job and datafeed.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Dynamic Resolution
    * ID: T1568
    * Reference URL: [https://attack.mitre.org/techniques/T1568/](https://attack.mitre.org/techniques/T1568/)



