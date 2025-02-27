---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-windows-network-activity.html
---

# Unusual Windows Network Activity [prebuilt-rule-8-17-4-unusual-windows-network-activity]

Identifies Windows processes that do not usually use the network but have unexpected network activity, which can indicate command-and-control, lateral movement, persistence, or data exfiltration activity. A process with unusual network activity can denote process exploitation or injection, where the process is used to run persistence mechanisms that allow a malicious actor remote access or control of the host, data exfiltration, and execution of unauthorized network applications.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4635]

**Triage and analysis**

**Investigating Unusual Windows Network Activity**

Detection alerts from this rule indicate the presence of network activity from a Windows process for which network activity is very unusual.  Here are some possible avenues of investigation: - Consider the IP addresses, protocol and ports. Are these used by normal but infrequent network workflows? Are they expected or unexpected? - If the destination IP address is remote or external, does it associate with an expected domain, organization or geography? Note: avoid interacting directly with suspected malicious IP addresses. - Consider the user as identified by the username field. Is this network activity part of an expected workflow for the user who ran the program? - Examine the history of execution. If this process only manifested recently, it might be part of a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process. - Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks it is performing. - Consider the same for the parent process. If the parent process is a legitimate system utility or service, this could be related to software updates or system management. If the parent process is something user-facing like an Office application, this process could be more suspicious. - If you have file hash values in the event data, and you suspect malware, you can optionally run a search for the file hash to see if the file is identified as malware by anti-malware tools.


## Setup [_setup_1467]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Windows

**Anomaly Detection Setup**

Once the rule is enabled, the associated Machine Learning job will start automatically. You can view the Machine Learning job linked under the "Definition" panel of the detection rule. If the job does not start due to an error, the issue must be resolved for the job to commence successfully. For more details on setting up anomaly detection jobs, refer to the [helper guide](docs-content://explore-analyze/machine-learning/anomaly-detection.md).

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration to your system:**

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

**Windows Integration Setup**

The Windows integration allows you to monitor the Windows OS, services, applications, and more.

**The following steps should be executed in order to add the Elastic Agent System integration "windows" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Windows” and select the integration to see more details about it.
* Click “Add Windows”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “windows” to an existing or a new agent policy, and deploy the agent on your system from which windows log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/windows).


