---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/accepted-default-telnet-port-connection.html
---

# Accepted Default Telnet Port Connection [accepted-default-telnet-port-connection]

This rule detects network events that may indicate the use of Telnet traffic. Telnet is commonly used by system administrators to remotely control older or embedded systems using the command line shell. It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector. As a plain-text protocol, it may also expose usernames and passwords to anyone capable of observing the traffic.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.panos*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* Use Case: Threat Detection
* Tactic: Command and Control
* Tactic: Lateral Movement
* Tactic: Initial Access
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_112]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Accepted Default Telnet Port Connection**

Telnet, a protocol for remote command-line access, is often used in legacy systems. Its lack of encryption makes it vulnerable, allowing attackers to intercept credentials or use it as a backdoor. The detection rule identifies unencrypted Telnet traffic on port 23, flagging connections that bypass typical security measures, thus highlighting potential unauthorized access attempts.

**Possible investigation steps**

* Review the network traffic logs to identify the source IP address associated with the Telnet connection on port 23. Determine if the source IP is internal or external to the organization.
* Check the destination IP address to ascertain if it belongs to a critical system or a legacy device that might still use Telnet for management purposes.
* Investigate the timeline of the connection event to see if there are any patterns or repeated attempts, which could indicate a persistent threat or automated attack.
* Analyze any associated user accounts or credentials used during the Telnet session to verify if they are legitimate and authorized for remote access.
* Correlate the Telnet connection event with other security alerts or logs to identify any related suspicious activities, such as failed login attempts or unusual data transfers.
* Assess the network segment where the Telnet traffic was detected to determine if it is appropriately segmented and secured against unauthorized access.
* Consider implementing network security measures, such as disabling Telnet on devices or replacing it with secure alternatives like SSH, to prevent future unauthorized access attempts.

**False positive analysis**

* Legacy systems or devices that require Telnet for management may trigger alerts. To manage this, create exceptions for specific IP addresses or subnets known to host these systems.
* Internal network monitoring tools that use Telnet for legitimate purposes might be flagged. Identify these tools and exclude their traffic from the rule to prevent unnecessary alerts.
* Lab environments or test networks where Telnet is used for educational or testing purposes can cause false positives. Implement network segmentation and apply exceptions to these environments to reduce noise.
* Automated scripts or maintenance tasks that utilize Telnet for routine operations may be mistakenly identified. Document these tasks and whitelist their associated traffic patterns to avoid false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any active Telnet sessions on the affected system to disrupt potential attacker activities.
* Conduct a thorough review of system logs and network traffic to identify any unauthorized access or data manipulation that may have occurred.
* Change all credentials that may have been exposed through Telnet traffic, prioritizing those with administrative privileges.
* Implement network segmentation to restrict Telnet access to only necessary internal systems, ensuring it is not exposed to the internet.
* Deploy encryption protocols such as SSH to replace Telnet for remote command-line access, enhancing security for remote management.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for additional security measures.


## Rule query [_rule_query_116]

```js
(event.dataset:network_traffic.flow or event.category:(network or network_traffic))
    and event.type:connection and not event.action:(
        flow_dropped or flow_denied or denied or deny or
        flow_terminated or timeout or Reject or network_flow)
    and destination.port:23
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



