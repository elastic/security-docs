---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-data-encryption-via-openssl-utility.html
---

# Suspicious Data Encryption via OpenSSL Utility [suspicious-data-encryption-via-openssl-utility]

Identifies when the openssl command-line utility is used to encrypt multiple files on a host within a short time window. Adversaries may encrypt data on a single or multiple systems in order to disrupt the availability of their target’s data and may attempt to hold the organization’s data to ransom for the purposes of extortion.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/](https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/)
* [https://www.trendmicro.com/en_us/research/21/f/bash-ransomware-darkradiation-targets-red-hat—​and-debian-based-linux-distributions.html](https://www.trendmicro.com/en_us/research/21/f/bash-ransomware-darkradiation-targets-red-hat—​and-debian-based-linux-distributions.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Impact
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_978]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Data Encryption via OpenSSL Utility**

OpenSSL is a widely-used command-line tool for secure data encryption and decryption. Adversaries may exploit OpenSSL to encrypt files rapidly across systems, aiming to disrupt data availability or demand ransom. The detection rule identifies suspicious OpenSSL usage by monitoring rapid file encryption activities, focusing on specific command patterns and excluding benign operations, thus highlighting potential malicious behavior.

**Possible investigation steps**

* Review the process execution details on the host identified by host.id to confirm the presence of the openssl command and its associated arguments, ensuring they match the suspicious pattern specified in the query.
* Examine the user.name associated with the process to determine if the activity aligns with expected behavior for that user or if it indicates potential unauthorized access.
* Investigate the parent process identified by process.parent.entity_id to understand the context in which the openssl command was executed, checking for any unusual or unexpected parent processes.
* Check for any recent file modifications or creations on the host that coincide with the time window of the alert to assess the impact of the encryption activity.
* Look for additional related alerts or logs from the same host or user within a similar timeframe to identify any patterns or further suspicious activities that could indicate a broader attack.

**False positive analysis**

* Legitimate batch encryption operations by system administrators or automated scripts may trigger the rule. To handle this, identify and whitelist specific scripts or user accounts that perform regular encryption tasks.
* Backup processes that use OpenSSL for encrypting data before storage can be mistaken for malicious activity. Exclude known backup processes by specifying their parent process names or paths.
* Developers or security teams testing encryption functionalities might inadvertently match the rule’s criteria. Create exceptions for development environments or specific user accounts involved in testing.
* Automated data transfer services that encrypt files for secure transmission could be flagged. Identify these services and exclude their associated processes or user accounts from the rule.
* Regularly review and update the exclusion list to ensure it reflects current operational practices and does not inadvertently allow malicious activities.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further spread of the encryption activity and potential lateral movement by the adversary.
* Terminate any suspicious OpenSSL processes identified on the host to halt ongoing encryption activities.
* Conduct a forensic analysis of the affected host to identify the scope of the encryption, including which files were encrypted and any potential data exfiltration.
* Restore encrypted files from the most recent clean backup to ensure data availability and integrity, ensuring that the backup is free from any malicious alterations.
* Change all credentials and keys that may have been exposed or used on the affected host to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and logging for OpenSSL usage across the network to detect and respond to similar threats more effectively in the future.


## Setup [_setup_621]

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


## Rule query [_rule_query_1026]

```js
sequence by host.id, user.name, process.parent.entity_id with maxspan=5s
  [ process where host.os.type == "linux" and event.action == "exec" and
    process.name == "openssl" and process.parent.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "perl*", "php*", "python*", "xargs") and
    process.args == "-in" and process.args == "-out" and
    process.args in ("-k", "-K", "-kfile", "-pass", "-iv", "-md") and
    /* excluding base64 encoding options and including encryption password or key params */
    not process.args in ("-d", "-a", "-A", "-base64", "-none", "-nosalt") ] with runs=10
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



