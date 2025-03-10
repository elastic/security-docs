---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-syn-based-port-scan-detected.html
---

# Potential SYN-Based Port Scan Detected [prebuilt-rule-8-17-3-potential-syn-based-port-scan-detected]

This rule identifies a potential SYN-Based port scan. A SYN port scan is a technique employed by attackers to scan a target network for open ports by sending SYN packets to multiple ports and observing the response. Attackers use this method to identify potential entry points or services that may be vulnerable to exploitation, allowing them to launch targeted attacks or gain unauthorized access to the system or network, compromising its security and potentially leading to data breaches or further malicious activities. This rule proposes threshold logic to check for connection attempts from one source host to 10 or more destination ports using 2 or less packets per port.

**Rule type**: threshold

**Rule indices**:

* logs-endpoint.events.network-*
* logs-network_traffic.*
* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-panw.panos*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 5

**References**: None

**Tags**:

* Domain: Network
* Tactic: Discovery
* Tactic: Reconnaissance
* Use Case: Network Security Monitoring
* Data Source: Elastic Defend
* Data Source: PAN-OS

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4955]

```js
destination.port : * and network.packets <= 2 and source.ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Service Discovery
    * ID: T1046
    * Reference URL: [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)

* Tactic:

    * Name: Reconnaissance
    * ID: TA0043
    * Reference URL: [https://attack.mitre.org/tactics/TA0043/](https://attack.mitre.org/tactics/TA0043/)

* Technique:

    * Name: Active Scanning
    * ID: T1595
    * Reference URL: [https://attack.mitre.org/techniques/T1595/](https://attack.mitre.org/techniques/T1595/)

* Sub-technique:

    * Name: Scanning IP Blocks
    * ID: T1595.001
    * Reference URL: [https://attack.mitre.org/techniques/T1595/001/](https://attack.mitre.org/techniques/T1595/001/)



