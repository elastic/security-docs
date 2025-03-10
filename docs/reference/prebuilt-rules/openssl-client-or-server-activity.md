---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/openssl-client-or-server-activity.html
---

# Openssl Client or Server Activity [openssl-client-or-server-activity]

This rule identifies when the openssl client or server is used to establish a connection. Attackers may use openssl to establish a secure connection to a remote server or to create a secure server to receive connections. This activity may be used to exfiltrate data or establish a command and control channel.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/openssl/](https://gtfobins.github.io/gtfobins/openssl/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_610]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Openssl Client or Server Activity**

OpenSSL is a widely-used toolkit for implementing secure communication via SSL/TLS protocols. In Linux environments, it can function as a client or server to encrypt data transmissions. Adversaries may exploit OpenSSL to establish encrypted channels for data exfiltration or command and control. The detection rule identifies suspicious OpenSSL usage by monitoring process execution patterns, specifically targeting atypical client-server interactions, while excluding known benign processes.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the "openssl" process with arguments indicating client or server activity, such as "s_client" with "-connect" or "s_server" with "-port".
* Check the parent process of the "openssl" execution to determine if it is a known benign process or if it is potentially suspicious, especially if it is not in the excluded list (e.g., "/pro/xymon/client/ext/awsXymonCheck.sh", "/opt/antidot-svc/nrpe/plugins/check_cert").
* Investigate the network connections established by the "openssl" process to identify the remote server’s IP address and port, and assess whether these are known or potentially malicious.
* Analyze the timing and frequency of the "openssl" executions to determine if they align with normal operational patterns or if they suggest unusual or unauthorized activity.
* Correlate the "openssl" activity with other security events or logs to identify any related suspicious behavior, such as data exfiltration attempts or command and control communications.

**False positive analysis**

* Known benign processes such as "/pro/xymon/client/ext/awsXymonCheck.sh" and "/opt/antidot-svc/nrpe/plugins/check_cert" are already excluded to reduce false positives. Ensure these paths are accurate and up-to-date in your environment.
* Regularly review and update the list of excluded parent processes to include any additional internal scripts or monitoring tools that frequently use OpenSSL for legitimate purposes.
* Monitor for any internal applications or services that may use OpenSSL in a similar manner and consider adding them to the exclusion list if they are verified as non-threatening.
* Implement logging and alerting to track the frequency and context of OpenSSL usage, which can help identify patterns that are consistently benign and warrant exclusion.
* Engage with system administrators to understand routine OpenSSL usage patterns in your environment, which can inform further refinement of the detection rule to minimize false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further data exfiltration or command and control activities.
* Terminate the suspicious OpenSSL process identified by the alert to halt any ongoing unauthorized encrypted communications.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unusual network connections or unauthorized file access.
* Review and update firewall rules to block unauthorized outbound connections from the affected system, focusing on the ports and IP addresses involved in the suspicious activity.
* Reset credentials and review access permissions for accounts on the affected system to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat has spread to other systems.
* Implement enhanced monitoring and logging for OpenSSL usage across the network to detect similar activities in the future, ensuring that alerts are promptly reviewed and acted upon.


## Setup [_setup_396]

**Setup**

This rule requires data coming in from Elastic Defend.

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


## Rule query [_rule_query_652]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
  process.name == "openssl" and (
    (process.args == "s_client" and process.args : ("-connect", "*:*") and not process.args == "-showcerts") or
    (process.args == "s_server" and process.args == "-port")
  ) and
  not process.parent.executable in (
    "/pro/xymon/client/ext/awsXymonCheck.sh", "/opt/antidot-svc/nrpe/plugins/check_cert", "/etc/zabbix/scripts/check_dane_tlsa.sh"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



