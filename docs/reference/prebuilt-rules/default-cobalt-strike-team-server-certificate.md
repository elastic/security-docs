---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/default-cobalt-strike-team-server-certificate.html
---

# Default Cobalt Strike Team Server Certificate [default-cobalt-strike-team-server-certificate]

This rule detects the use of the default Cobalt Strike Team Server TLS certificate. Cobalt Strike is software for Adversary Simulations and Red Team Operations which are security assessments that replicate the tactics and techniques of an advanced adversary in a network. Modifications to the Packetbeat configuration can be made to include MD5 and SHA256 hashing algorithms (the default is SHA1). See the References section for additional information on module configuration.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*

**Severity**: critical

**Risk score**: 99

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/software/S0154/](https://attack.mitre.org/software/S0154/)
* [https://www.cobaltstrike.com/help-setup-collaboration](https://www.cobaltstrike.com/help-setup-collaboration)
* [/beats/docs/reference/ingestion-tools/beats-packetbeat/configuration-tls.md](beats://docs/reference/packetbeat/configuration-tls.md)
* [https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-suricata.html](https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-suricata.html)
* [https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-zeek.html](https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-zeek.html)
* [https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack](https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack)

**Tags**:

* Tactic: Command and Control
* Threat: Cobalt Strike
* Use Case: Threat Detection
* Domain: Endpoint
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_263]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Default Cobalt Strike Team Server Certificate**

Cobalt Strike is a tool used for simulating advanced cyber threats, often employed by security teams to test defenses. However, adversaries can exploit its default server certificate to establish covert command and control channels. The detection rule identifies this misuse by monitoring network traffic for specific cryptographic hashes associated with the default certificate, flagging potential unauthorized Cobalt Strike activity.

**Possible investigation steps**

* Review the network traffic logs to identify any connections associated with the specific cryptographic hashes: MD5 (950098276A495286EB2A2556FBAB6D83), SHA1 (6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C), or SHA256 (87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C).
* Identify the source and destination IP addresses involved in the flagged network traffic to determine the potential origin and target of the Cobalt Strike activity.
* Correlate the identified IP addresses with known assets in the network to assess if any internal systems are potentially compromised.
* Check for any other suspicious or anomalous network activities around the same time as the alert to identify potential lateral movement or additional command and control channels.
* Investigate any associated processes or user accounts on the involved systems to determine if there are signs of compromise or unauthorized access.
* Review historical data to see if there have been previous alerts or similar activities involving the same cryptographic hashes or IP addresses, which might indicate a persistent threat.

**False positive analysis**

* Legitimate security testing activities by internal teams using Cobalt Strike may trigger the rule. Coordinate with security teams to whitelist known testing IP addresses or certificate hashes.
* Some commercial penetration testing services may use Cobalt Strike with default certificates. Verify the legitimacy of such services and exclude their traffic from detection by adding their certificate hashes to an exception list.
* Network appliances or security tools that simulate adversary behavior for training purposes might use similar certificates. Identify these tools and configure exceptions for their specific network traffic patterns.
* In environments where Cobalt Strike is used for authorized red team exercises, ensure that the default certificate is replaced with a custom one to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further communication with the potential Cobalt Strike server.
* Conduct a thorough forensic analysis of the isolated system to identify any malicious payloads or additional indicators of compromise.
* Revoke any compromised credentials and enforce a password reset for affected accounts to prevent unauthorized access.
* Update and patch all systems to the latest security standards to mitigate vulnerabilities that could be exploited by similar threats.
* Implement network segmentation to limit the lateral movement of threats within the network.
* Enhance monitoring and logging to capture detailed network traffic and endpoint activity, focusing on the identified cryptographic hashes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and coordination with external threat intelligence sources if necessary.

**Threat intel**

While Cobalt Strike is intended to be used for penetration tests and IR training, it is frequently used by actual threat actors (TA) such as APT19, APT29, APT32, APT41, FIN6, DarkHydrus, CopyKittens, Cobalt Group, Leviathan, and many other unnamed criminal TAs. This rule uses high-confidence atomic indicators, so alerts should be investigated rapidly.


## Rule query [_rule_query_273]

```js
(event.dataset: network_traffic.tls or event.category: (network or network_traffic))
  and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83
  or tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C
  or tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
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

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)



