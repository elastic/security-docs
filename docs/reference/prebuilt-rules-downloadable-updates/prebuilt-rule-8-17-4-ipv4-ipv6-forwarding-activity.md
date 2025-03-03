---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ipv4-ipv6-forwarding-activity.html
---

# IPv4/IPv6 Forwarding Activity [prebuilt-rule-8-17-4-ipv4-ipv6-forwarding-activity]

This rule monitors for the execution of commands that enable IPv4 and IPv6 forwarding on Linux systems. Enabling IP forwarding can be used to route network traffic between different network interfaces, potentially allowing attackers to pivot between networks, exfiltrate data, or establish command and control channels.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4304]

**Triage and analysis**

[TBC: QUOTE]
**Investigating IPv4/IPv6 Forwarding Activity**

IPv4/IPv6 forwarding allows a Linux system to route traffic between network interfaces, facilitating network communication. While essential for legitimate network operations, adversaries can exploit this capability to pivot across networks, exfiltrate data, or maintain control channels. The detection rule identifies suspicious command executions that enable IP forwarding, focusing on specific command patterns and processes, thus highlighting potential misuse.

**Possible investigation steps**

* Review the process command line details to understand the context in which IP forwarding was enabled, focusing on the specific command patterns identified in the alert.
* Identify the parent process of the suspicious command execution using the process.parent.executable field to determine if it was initiated by a legitimate or potentially malicious process.
* Check the user account associated with the process execution to assess if the action was performed by an authorized user or if there are signs of compromised credentials.
* Investigate recent network activity on the host to identify any unusual traffic patterns or connections that could indicate data exfiltration or lateral movement.
* Correlate the alert with other security events or logs from the same host or network segment to identify any related suspicious activities or patterns.
* Assess the system’s current configuration and network topology to determine if enabling IP forwarding could have been part of a legitimate administrative task or if it poses a security risk.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators enable IP forwarding for legitimate network configuration purposes. To manage this, create exceptions for known administrative scripts or processes that regularly perform these actions.
* Automated scripts or configuration management tools like Ansible or Puppet might execute commands that match the rule’s criteria. Identify these tools and exclude their processes from the rule to prevent false alerts.
* Network testing or troubleshooting activities often require temporary enabling of IP forwarding. Document and exclude these activities when performed by trusted users or during scheduled maintenance windows.
* Virtualization or container orchestration platforms may enable IP forwarding as part of their normal operations. Recognize these platforms and adjust the rule to ignore their specific processes or command patterns.
* Security tools or network monitoring solutions might also enable IP forwarding for analysis purposes. Verify these tools and exclude their processes to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected Linux system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, particularly those enabling IP forwarding, to halt potential lateral movement or data exfiltration.
* Conduct a thorough review of network traffic logs to identify any unusual or unauthorized connections that may indicate command and control activity.
* Revert any unauthorized changes to system configurations, specifically those related to IP forwarding settings, to restore the system to its secure state.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are compromised.
* Implement network segmentation to limit the ability of attackers to pivot between networks in the future.
* Enhance monitoring and alerting for similar suspicious activities by tuning detection systems to recognize patterns associated with IP forwarding misuse.


## Rule query [_rule_query_5296]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "exec_event") and
process.parent.executable != null and process.command_line like (
  "*net.ipv4.ip_forward*", "*/proc/sys/net/ipv4/ip_forward*", "*net.ipv6.conf.all.forwarding*",
  "*/proc/sys/net/ipv6/conf/all/forwarding*"
) and (
  (process.name == "sysctl" and process.args like ("*-w*", "*--write*", "*=*")) or
  (
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and
    process.command_line like "*echo *"
  )
) and
not process.parent.name like~ ("privsep-helper", "platform-python*", "init.ipv6-global", "wsl-bootstrap")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



