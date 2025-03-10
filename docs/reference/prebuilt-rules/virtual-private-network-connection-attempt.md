---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/virtual-private-network-connection-attempt.html
---

# Virtual Private Network Connection Attempt [virtual-private-network-connection-attempt]

Identifies the execution of macOS built-in commands to connect to an existing Virtual Private Network (VPN). Adversaries may use VPN connections to laterally move and control remote systems on a network.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/vpn.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/vpn.rb)
* [https://www.unix.com/man-page/osx/8/networksetup/](https://www.unix.com/man-page/osx/8/networksetup/)
* [https://superuser.com/questions/358513/start-configured-vpn-from-command-line-osx](https://superuser.com/questions/358513/start-configured-vpn-from-command-line-osx)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1183]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Virtual Private Network Connection Attempt**

Virtual Private Networks (VPNs) are used to securely connect to remote networks, encrypting data and masking IP addresses. Adversaries may exploit VPNs to move laterally within a network, gaining unauthorized access to systems. The detection rule identifies suspicious VPN connection attempts on macOS by monitoring specific command executions, helping to flag potential misuse for further investigation.

**Possible investigation steps**

* Review the process details to confirm the legitimacy of the VPN connection attempt by examining the process name and arguments, such as "networksetup" with "-connectpppoeservice", "scutil" with "--nc start", or "osascript" with "osascript*set VPN to service*".
* Check the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Investigate the source IP address and destination network to assess if the connection is to a known and trusted network or if it is unusual for the environment.
* Analyze historical data for similar VPN connection attempts from the same user or device to identify patterns or repeated unauthorized access attempts.
* Correlate the VPN connection attempt with other security events or alerts to identify potential lateral movement or further malicious activity within the network.

**False positive analysis**

* Legitimate VPN usage by IT staff or network administrators may trigger the rule. To manage this, create exceptions for known user accounts or specific times when VPN maintenance is scheduled.
* Automated scripts or applications that use macOS built-in commands for VPN connections can cause false positives. Identify these scripts and whitelist their process names or command lines.
* Frequent VPN connections from trusted devices or IP addresses might be flagged. Exclude these devices or IPs from the rule to reduce noise.
* Users who frequently travel and connect to corporate networks via VPN may trigger alerts. Consider excluding these users or implementing a separate monitoring strategy for their activities.
* Regularly review and update the exclusion list to ensure it reflects current network policies and user behaviors, minimizing unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS device from the network to prevent further lateral movement by the adversary.
* Terminate any suspicious VPN connections identified by the detection rule to cut off unauthorized access.
* Conduct a thorough review of the affected system’s VPN configuration and logs to identify any unauthorized changes or connections.
* Reset credentials and update authentication methods for VPN access to ensure that compromised credentials are not reused.
* Escalate the incident to the security operations center (SOC) for further analysis and to determine if other systems have been affected.
* Implement additional monitoring on the network for unusual VPN connection attempts or related suspicious activities to enhance detection capabilities.
* Review and update VPN access policies to ensure they align with current security best practices and limit access to only necessary users and systems.


## Setup [_setup_751]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_1206]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    (process.name : "networksetup" and process.args : "-connectpppoeservice") or
    (process.name : "scutil" and process.args : "--nc" and process.args : "start") or
    (process.name : "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)



