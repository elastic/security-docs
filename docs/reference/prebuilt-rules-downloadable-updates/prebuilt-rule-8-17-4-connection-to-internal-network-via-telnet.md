---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-connection-to-internal-network-via-telnet.html
---

# Connection to Internal Network via Telnet [prebuilt-rule-8-17-4-connection-to-internal-network-via-telnet]

Telnet provides a command line interface for communication with a remote device or server. This rule identifies Telnet network connections to non-publicly routable IP addresses.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4434]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Connection to Internal Network via Telnet**

Telnet is a protocol offering a command-line interface for remote device management, often used in network environments. Adversaries may exploit Telnet to move laterally within a network, accessing non-public IPs to execute commands or exfiltrate data. The detection rule identifies Telnet connections to internal IP ranges, flagging potential unauthorized access attempts, thus aiding in early threat detection and response.

**Possible investigation steps**

* Review the process details to confirm the Telnet connection initiation by examining the process.entity_id and process.name fields to ensure the process is indeed Telnet.
* Analyze the destination IP address to determine if it falls within the specified non-public IP ranges, indicating an internal network connection attempt.
* Check the event.type field to verify that the Telnet process event is of type "start", confirming the initiation of a connection.
* Investigate the source host by reviewing host.os.type and other relevant host details to understand the context and legitimacy of the connection attempt.
* Correlate the Telnet activity with any other suspicious network or process activities on the same host to identify potential lateral movement or data exfiltration attempts.
* Consult historical logs and alerts to determine if there have been previous similar Telnet connection attempts from the same source, which might indicate a pattern or ongoing threat.

**False positive analysis**

* Routine administrative tasks using Telnet within internal networks can trigger false positives. To manage this, create exceptions for known IP addresses or specific user accounts that regularly perform these tasks.
* Automated scripts or monitoring tools that use Telnet for legitimate purposes may be flagged. Identify these scripts and whitelist their associated processes or IP addresses to prevent unnecessary alerts.
* Internal testing environments often simulate network activities, including Telnet connections. Exclude IP ranges associated with these environments to reduce false positives.
* Legacy systems that rely on Telnet for communication might generate alerts. Document these systems and apply exceptions based on their IP addresses or hostnames to avoid repeated false positives.
* Regularly review and update the list of excluded IPs and processes to ensure that only legitimate activities are exempted, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further lateral movement or data exfiltration.
* Terminate any active Telnet sessions on the affected host to stop unauthorized access.
* Conduct a thorough review of the affected host’s system logs and Telnet session logs to identify any unauthorized commands executed or data accessed.
* Change all credentials that may have been exposed or used during the unauthorized Telnet sessions to prevent further unauthorized access.
* Apply security patches and updates to the affected host and any other systems that may be vulnerable to similar exploitation.
* Implement network segmentation to limit Telnet access to only necessary systems and ensure that Telnet is disabled on systems where it is not required.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_1277]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_5426]

```js
sequence by process.entity_id
  [process where host.os.type == "linux" and process.name == "telnet" and event.type == "start"]
  [network where host.os.type == "linux" and process.name == "telnet" and cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  ]
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



