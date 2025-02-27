---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-preload-environment-variable-process-execution.html
---

# Unusual Preload Environment Variable Process Execution [prebuilt-rule-8-17-4-unusual-preload-environment-variable-process-execution]

This rule detects processes that are executed with environment variables that are not commonly used. This could indicate an attacker is attempting to hijack the execution flow of a process by loading malicious libraries or binaries into the process memory space.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*

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
* Tactic: Defense Evasion
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4362]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Preload Environment Variable Process Execution**

In Linux environments, preload environment variables can dictate which libraries are loaded into a process, potentially altering its behavior. Adversaries exploit this by injecting malicious libraries to hijack execution flow, achieving persistence or evasion. The detection rule identifies atypical environment variables during process execution, signaling potential misuse by attackers.

**Possible investigation steps**

* Review the process details associated with the alert, focusing on the process name, command line, and any unusual environment variables listed in process.env_vars.
* Investigate the parent process to understand the context of how the process was initiated and whether it aligns with expected behavior.
* Check the history of the process and its associated user account to identify any recent changes or suspicious activities that might indicate compromise.
* Analyze the libraries or binaries specified in the environment variables to determine if they are legitimate or potentially malicious.
* Cross-reference the process and environment variables with known threat intelligence sources to identify any matches with known malicious activity.
* Examine system logs and other related alerts around the same timeframe to identify any correlated or supporting evidence of malicious activity.

**False positive analysis**

* Development and testing environments often use custom preload variables to test new libraries, which can trigger false positives. Users should identify and whitelist these known variables to prevent unnecessary alerts.
* Some legitimate software applications may use uncommon preload environment variables for performance optimization or compatibility reasons. Users can create exceptions for these applications by verifying their source and behavior.
* System administrators might employ preload variables for system tuning or debugging purposes. Documenting and excluding these specific cases can help reduce false positives.
* Security tools and monitoring solutions might use preload variables as part of their operation. Ensure these tools are recognized and excluded from triggering alerts by maintaining an updated list of their known behaviors.
* Regularly review and update the list of excluded variables and processes to adapt to changes in the environment and software updates, ensuring that only non-threatening behaviors are excluded.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified with unusual preload environment variables to halt potential malicious execution.
* Conduct a thorough review of the affected system’s environment variables and loaded libraries to identify and remove any unauthorized or malicious entries.
* Restore the affected system from a known good backup to ensure all malicious modifications are removed.
* Update and patch the system to the latest security standards to mitigate vulnerabilities that could be exploited for similar attacks.
* Monitor the network and system logs for any signs of re-infection or similar suspicious activity, focusing on process execution patterns.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Setup [_setup_1209]

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

Elastic Defend integration does not collect environment variable logging by default. In order to capture this behavior, this rule requires a specific configuration option set within the advanced settings of the Elastic Defend integration. ## To set up environment variable capture for an Elastic Agent policy: - Go to “Security → Manage → Policies”. - Select an “Elastic Agent policy”. - Click “Show advanced settings”. - Scroll down or search for “linux.advanced.capture_env_vars”. - Enter the names of environment variables you want to capture, separated by commas. - For this rule the linux.advanced.capture_env_vars variable should be set to "LD_PRELOAD,LD_LIBRARY_PATH". - Click “Save”. After saving the integration change, the Elastic Agents running this policy will be updated and the rule will function properly. For more information on capturing environment variables refer to the [helper guide](docs-content://solutions/security/cloud/capture-environment-variables.md).


## Rule query [_rule_query_5354]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and process.env_vars:*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



