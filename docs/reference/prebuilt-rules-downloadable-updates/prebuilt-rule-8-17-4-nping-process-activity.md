---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-nping-process-activity.html
---

# Nping Process Activity [prebuilt-rule-8-17-4-nping-process-activity]

Nping ran on a Linux host. Nping is part of the Nmap tool suite and has the ability to construct raw packets for a wide variety of security testing applications, including denial of service testing.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://en.wikipedia.org/wiki/Nmap](https://en.wikipedia.org/wiki/Nmap)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4370]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Nping Process Activity**

Nping, a component of the Nmap suite, is used for crafting raw packets, aiding in network diagnostics and security testing. Adversaries may exploit Nping to perform network reconnaissance or denial-of-service attacks by sending crafted packets to probe network services. The detection rule identifies Nping’s execution on Linux systems by monitoring process start events, helping to flag potential misuse for malicious network discovery activities.

**Possible investigation steps**

* Review the process start event details to confirm the execution of Nping, focusing on the process name field to ensure it matches "nping".
* Identify the user account associated with the Nping process execution to determine if it aligns with expected or authorized usage patterns.
* Examine the command line arguments used with Nping to understand the intent of the execution, such as specific network targets or packet types.
* Check the timing and frequency of the Nping execution to assess if it correlates with any known maintenance windows or unusual activity patterns.
* Investigate network logs or traffic data to identify any unusual or unauthorized network scanning or probing activities originating from the host where Nping was executed.
* Correlate the Nping activity with other security alerts or logs from the same host to identify potential indicators of compromise or broader attack patterns.

**False positive analysis**

* Routine network diagnostics by IT teams using Nping for legitimate purposes can trigger alerts. To manage this, create exceptions for specific user accounts or IP addresses known to perform regular network testing.
* Automated scripts or monitoring tools that incorporate Nping for network health checks may cause false positives. Identify these scripts and whitelist their execution paths or associated processes.
* Security assessments or penetration tests conducted by authorized personnel might involve Nping usage. Coordinate with security teams to schedule these activities and temporarily adjust detection rules or add exceptions for the duration of the tests.
* Development or testing environments where Nping is used for application testing can generate alerts. Exclude these environments from monitoring or adjust the rule to ignore specific hostnames or network segments.
* Training sessions or workshops that include Nping demonstrations can lead to false positives. Notify the security team in advance and apply temporary exceptions for the event duration.

**Response and remediation**

* Immediately isolate the affected Linux host from the network to prevent further reconnaissance or potential denial-of-service attacks.
* Terminate the Nping process on the affected host to stop any ongoing malicious activity.
* Conduct a thorough review of recent network traffic logs from the affected host to identify any unusual or unauthorized network service discovery attempts.
* Check for any unauthorized changes or installations on the affected host that may indicate further compromise or persistence mechanisms.
* Update and apply network security policies to restrict the use of network diagnostic tools like Nping to authorized personnel only.
* Escalate the incident to the security operations team for further investigation and to determine if the activity is part of a larger attack campaign.
* Enhance monitoring and alerting for similar activities across the network by ensuring that detection rules are in place for unauthorized use of network diagnostic tools.


## Setup [_setup_1217]

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


## Rule query [_rule_query_5362]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name == "nping"
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



