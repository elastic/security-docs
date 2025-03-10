---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/inbound-connection-to-an-unsecure-elasticsearch-node.html
---

# Inbound Connection to an Unsecure Elasticsearch Node [inbound-connection-to-an-unsecure-elasticsearch-node]

Identifies Elasticsearch nodes that do not have Transport Layer Security (TLS), and/or lack authentication, and are accepting inbound network connections over the default Elasticsearch port.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* logs-network_traffic.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [docs-content://deploy-manage/deploy/self-managed/installing-elasticsearch.md](docs-content://deploy-manage/deploy/self-managed/installing-elasticsearch.md)
* [/beats/docs/reference/ingestion-tools/beats-packetbeat/packetbeat-http-options.md#_send_all_headers](beats://reference/packetbeat/packetbeat-http-options.md#_send_all_headers)

**Tags**:

* Use Case: Threat Detection
* Tactic: Initial Access
* Domain: Endpoint
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_424]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Inbound Connection to an Unsecure Elasticsearch Node**

Elasticsearch is a powerful search and analytics engine often used for log and data analysis. When improperly configured without TLS or authentication, it becomes vulnerable to unauthorized access. Adversaries can exploit these weaknesses to gain initial access, exfiltrate data, or disrupt services. The detection rule identifies unsecured nodes by monitoring inbound HTTP traffic on the default port, flagging connections lacking authentication headers, thus highlighting potential exploitation attempts.

**Possible investigation steps**

* Review the source IP address of the inbound connection to determine if it is from a known or trusted entity. Cross-reference with internal asset inventories or threat intelligence sources.
* Examine the network traffic logs for any unusual patterns or repeated access attempts from the same source IP, which might indicate a brute force or scanning activity.
* Check for any data exfiltration attempts by analyzing outbound traffic from the Elasticsearch node, focusing on large data transfers or connections to unfamiliar external IPs.
* Investigate the absence of authentication headers in the HTTP requests to confirm if the Elasticsearch node is indeed misconfigured and lacks proper security controls.
* Assess the configuration of the Elasticsearch node to ensure that TLS is enabled and authentication mechanisms are properly implemented to prevent unauthorized access.
* Look for any other alerts or logs related to the same Elasticsearch node or source IP to identify potential coordinated attack activities or previous incidents.

**False positive analysis**

* Internal monitoring tools or scripts that regularly check Elasticsearch node status without authentication can trigger false positives. Exclude these specific IP addresses or user agents from the rule to reduce noise.
* Automated backup systems that interact with Elasticsearch nodes without using authentication headers might be flagged. Identify these systems and create exceptions based on their IP addresses or network segments.
* Development or testing environments where Elasticsearch nodes are intentionally left unsecured for testing purposes can generate alerts. Use network segmentation or specific tags to differentiate these environments and exclude them from the rule.
* Security scans or vulnerability assessments conducted by internal teams may access Elasticsearch nodes without authentication, leading to false positives. Whitelist the IP ranges used by these security tools to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected Elasticsearch node from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of access logs to identify any unauthorized access or data exfiltration attempts, focusing on connections lacking authentication headers.
* Implement Transport Layer Security (TLS) and enable authentication mechanisms on the Elasticsearch node to secure communications and restrict access to authorized users only.
* Reset credentials and API keys associated with the Elasticsearch node to prevent further unauthorized access using potentially compromised credentials.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized access and steps taken to contain the threat.
* Monitor the network for any signs of continued unauthorized access attempts or related suspicious activity, adjusting detection rules as necessary to capture similar threats.
* Document the incident, including the response actions taken, and conduct a post-incident review to identify any gaps in security controls and improve future response efforts.


## Setup [_setup_272]

This rule requires the addition of port `9200` and `send_all_headers` to the `HTTP` protocol configuration in `packetbeat.yml`. See the References section for additional configuration documentation.


## Rule query [_rule_query_457]

```js
(event.dataset: network_traffic.http OR (event.category: network_traffic AND network.protocol: http)) AND
    status:OK AND destination.port:9200 AND network.direction:inbound AND NOT http.response.headers.content-type:"image/x-icon" AND NOT
    _exists_:http.request.headers.authorization
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



