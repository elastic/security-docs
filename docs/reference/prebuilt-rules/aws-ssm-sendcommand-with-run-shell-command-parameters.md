---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ssm-sendcommand-with-run-shell-command-parameters.html
---

# AWS SSM `SendCommand` with Run Shell Command Parameters [aws-ssm-sendcommand-with-run-shell-command-parameters]

Identifies the use of the AWS Systems Manager (SSM) `SendCommand` API with the either `AWS-RunShellScript` or `AWS-RunPowerShellScript` parameters. The `SendCommand` API call allows users to execute commands on EC2 instances using the SSM service. Adversaries may use this technique to execute commands on EC2 instances without the need for SSH or RDP access. This behavior may indicate an adversary attempting to execute commands on an EC2 instance for malicious purposes. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that only flags when this behavior is observed for the first time on a host in the last 7 days.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ssm-privesc](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ssm-privesc)
* [https://securitycafe.ro/2023/01/17/aws-post-explitation-with-ssm-sendcommand/](https://securitycafe.ro/2023/01/17/aws-post-explitation-with-ssm-sendcommand/)

**Tags**:

* Domain: Endpoint
* Domain: Cloud
* OS: Linux
* OS: macOS
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_96]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS SSM `SendCommand` with Run Shell Command Parameters**

AWS Systems Manager (SSM) allows remote command execution on EC2 instances via the `SendCommand` API, using scripts like `AWS-RunShellScript` or `AWS-RunPowerShellScript`. Adversaries may exploit this to execute unauthorized commands without direct access. The detection rule identifies unusual command executions by monitoring process activities, flagging first-time occurrences within a week to spot potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific EC2 instance and the user account associated with the `SendCommand` API call.
* Check the AWS CloudTrail logs for the `SendCommand` event to gather additional context, such as the source IP address, user agent, and any associated IAM roles or policies.
* Investigate the command parameters used in the `SendCommand` API call, focusing on the `commands` field to determine the nature and intent of the executed script.
* Examine the process execution history on the affected host to identify any unusual or unauthorized processes that may have been initiated as a result of the command.
* Assess the recent activity of the user account involved in the alert to identify any other suspicious actions or deviations from normal behavior.
* Verify the integrity and security posture of the affected EC2 instance, checking for any signs of compromise or unauthorized changes.

**False positive analysis**

* Routine administrative tasks using AWS SSM SendCommand may trigger alerts. Identify and document regular maintenance scripts and exclude them from detection to reduce noise.
* Automated deployment processes often use AWS-RunShellScript or AWS-RunPowerShellScript. Review deployment logs and whitelist these processes if they are verified as non-threatening.
* Monitoring or compliance checks that utilize SSM for gathering system information can be mistaken for malicious activity. Confirm these activities with the relevant teams and create exceptions for known benign operations.
* Scheduled tasks or cron jobs that execute commands via SSM should be reviewed. If they are part of standard operations, consider excluding them from the rule to prevent false positives.
* Development and testing environments frequently use SSM for testing scripts. Ensure these environments are well-documented and apply exceptions to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected EC2 instance from the network to prevent further unauthorized command execution and potential lateral movement.
* Review the AWS CloudTrail logs to identify the source of the `SendCommand` API call, including the IAM user or role that initiated the command, and assess whether the access was legitimate or compromised.
* Revoke or rotate the credentials of the IAM user or role involved in the suspicious activity to prevent further unauthorized access.
* Conduct a thorough examination of the affected EC2 instance to identify any unauthorized changes or installed malware, and restore the instance from a known good backup if necessary.
* Implement stricter IAM policies and permissions to limit the use of the `SendCommand` API to only trusted users and roles, ensuring the principle of least privilege is enforced.
* Enable multi-factor authentication (MFA) for all IAM users with permissions to execute commands on EC2 instances to add an additional layer of security.
* Escalate the incident to the security operations team for further investigation and to determine if additional instances or resources have been compromised.


## Setup [_setup_54]

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


## Rule query [_rule_query_100]

```js
event.category: "process" and event.type: "start" and process.name: "aws"
and (
    host.os.type: ("windows" or "macos")
    or (
        host.os.type: "linux"
        and event.action: ("exec" or "exec_event" or "executed" or "process_started")
    )
)
and process.args: (
    "send-command" and "--parameters" and commands=*
    and ("AWS-RunShellScript" or "AWS-RunPowerShellScript")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Cloud Administration Command
    * ID: T1651
    * Reference URL: [https://attack.mitre.org/techniques/T1651/](https://attack.mitre.org/techniques/T1651/)



