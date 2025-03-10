---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/privileged-docker-container-creation.html
---

# Privileged Docker Container Creation [privileged-docker-container-creation]

This rule leverages the new_terms rule type to identify the creation of a potentially unsafe docker container from an unusual parent process. Attackers can use the `--privileged` flag to create containers with escalated privileges, which can lead to trivial privilege escalation, docker escaping and persistence. access.

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
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_825]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privileged Docker Container Creation**

Docker containers are lightweight, portable units that package applications and their dependencies. The `--privileged` flag grants containers extensive host access, posing security risks. Adversaries exploit this to escalate privileges or escape containers. The detection rule identifies unusual privileged container creation by monitoring specific process actions and arguments, helping to flag potential threats early.

**Possible investigation steps**

* Review the alert details to confirm the presence of the `--privileged` flag in the process arguments, as indicated by the query field `process.args:(run and --privileged)`.
* Identify the parent process of the Docker command by examining the `event.category:process` and `event.type:start` fields to determine if it originates from an unusual or unauthorized source.
* Check the user account associated with the Docker process to verify if it has legitimate access and permissions to create privileged containers.
* Investigate the timeline of events leading up to the container creation by reviewing related logs and events around the `event.action:exec` to identify any suspicious activities or patterns.
* Assess the container’s configuration and running processes to determine if any unauthorized or potentially harmful applications are being executed within the container.
* Correlate the alert with other security events or alerts in the environment to identify potential indicators of compromise or broader attack patterns.

**False positive analysis**

* Routine administrative tasks may trigger the rule if system administrators use the --privileged flag for legitimate container management. To handle this, identify and document these tasks, then create exceptions for known administrative processes.
* Automated deployment scripts that require elevated privileges might also cause false positives. Review these scripts and whitelist them by specifying the parent process or script name in the exclusion criteria.
* Development environments often use privileged containers for testing purposes. To reduce noise, exclude processes originating from known development machines or user accounts.
* Some monitoring or security tools may use privileged containers for legitimate purposes. Verify these tools and add them to the exception list to prevent unnecessary alerts.
* Regularly review and update the exclusion list to ensure it reflects current operational practices and does not inadvertently allow malicious activity.

**Response and remediation**

* Immediately isolate the affected container to prevent further interaction with the host system. This can be done by stopping the container using `docker stop <container_id>`.
* Review and revoke any unnecessary permissions or access rights granted to the container. Ensure that the `--privileged` flag is not used unless absolutely necessary.
* Conduct a thorough investigation of the container’s filesystem and running processes to identify any malicious activity or unauthorized changes. Use tools like `docker exec` to inspect the container’s environment.
* Check for any signs of container escape or host compromise by reviewing system logs and monitoring for unusual activity on the host machine.
* If a compromise is confirmed, initiate a full incident response procedure, including forensic analysis and system restoration from clean backups.
* Update and patch the Docker daemon and any related software to the latest versions to mitigate known vulnerabilities that could be exploited.
* Enhance monitoring and alerting for privileged container creation by integrating additional security tools or services that provide real-time threat intelligence and anomaly detection.


## Setup [_setup_542]

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


## Rule query [_rule_query_879]

```js
host.os.type:linux and event.category:process and event.type:start and event.action:exec and process.name:docker and
process.args:(run and --privileged)
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

* Technique:

    * Name: Container Administration Command
    * ID: T1609
    * Reference URL: [https://attack.mitre.org/techniques/T1609/](https://attack.mitre.org/techniques/T1609/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)



