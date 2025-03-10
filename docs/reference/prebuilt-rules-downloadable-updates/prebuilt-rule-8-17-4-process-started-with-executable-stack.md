---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-started-with-executable-stack.html
---

# Process Started with Executable Stack [prebuilt-rule-8-17-4-process-started-with-executable-stack]

This rule monitors the syslog log file for messages related to instances of processes that are started with an executable stack. This can be an indicator of a process that is attempting to execute code from the stack, which can be a security risk.

**Rule type**: query

**Rule indices**:

* logs-system.syslog-*

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
* Tactic: Execution
* Data Source: System
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4393]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Started with Executable Stack**

In Linux environments, processes with executable stacks can pose security risks as they may allow code execution from the stack, a behavior often exploited by attackers to run arbitrary code. Adversaries might leverage this to execute malicious scripts or commands. The detection rule monitors syslog for kernel messages indicating such processes, flagging potential threats for further investigation.

**Possible investigation steps**

* Review the syslog entries to identify the specific process that triggered the alert, focusing on the message field containing "started with executable stack".
* Investigate the process name and associated command-line arguments to understand the nature and purpose of the process.
* Check the process’s parent process to determine if it was spawned by a legitimate application or service.
* Analyze the user account under which the process is running to assess if it aligns with expected behavior and permissions.
* Look for any recent changes or anomalies in the system that might correlate with the process start time, such as new software installations or configuration changes.
* Cross-reference the process with known threat intelligence sources to identify if it matches any known malicious patterns or indicators.

**False positive analysis**

* Development tools and environments may intentionally use executable stacks for legitimate purposes, such as certain debugging or testing scenarios. Users can create exceptions for these specific tools by identifying their process names and excluding them from the detection rule.
* Some legacy applications might require executable stacks due to outdated coding practices. Users should verify the necessity of these applications and, if deemed non-threatening, add them to an exclusion list based on their process names or paths.
* Custom scripts or applications developed in-house might inadvertently use executable stacks. Conduct a review of these scripts to ensure they are safe, and if so, exclude them from monitoring by specifying their unique identifiers.
* Certain system utilities or libraries might trigger this rule during normal operations. Users should consult documentation or vendor support to confirm if these are expected behaviors and exclude them accordingly if they pose no risk.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the attacker.
* Terminate the suspicious process identified with an executable stack to halt any ongoing malicious activity.
* Conduct a thorough analysis of the process and its associated files to identify any malicious payloads or scripts that may have been executed.
* Restore the system from a known good backup if any unauthorized changes or malware are detected.
* Apply security patches and updates to the operating system and applications to mitigate vulnerabilities that could be exploited by similar threats.
* Implement stack protection mechanisms such as stack canaries or non-executable stack configurations to prevent future exploitation.
* Escalate the incident to the security operations team for further investigation and to assess the need for additional security measures.


## Setup [_setup_1237]

**Setup**

This rule requires data coming in from one of the following integrations: - Filebeat

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat for the Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete Setup and Run Filebeat information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the Filebeat System Module to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_5385]

```js
host.os.type:"linux" and event.dataset:"system.syslog" and process.name:"kernel" and
message:"started with executable stack"
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



