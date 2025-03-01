---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-virtual-private-cloud-network-deletion.html
---

# GCP Virtual Private Cloud Network Deletion [prebuilt-rule-8-17-4-gcp-virtual-private-cloud-network-deletion]

Identifies when a Virtual Private Cloud (VPC) network is deleted in Google Cloud Platform (GCP). A VPC network is a virtual version of a physical network within a GCP project. Each VPC network has its own subnets, routes, and firewall, as well as other elements. An adversary may delete a VPC network in order to disrupt their target’s network and business operations.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/vpc/docs/vpc](https://cloud.google.com/vpc/docs/vpc)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Configuration Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4169]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Virtual Private Cloud Network Deletion**

Google Cloud Platform’s Virtual Private Cloud (VPC) networks are essential for managing isolated network environments within a project, encompassing subnets, routes, and firewalls. Adversaries may target VPC deletions to disrupt operations and evade defenses. The detection rule monitors audit logs for successful VPC deletions, flagging potential malicious activity by correlating specific event actions and outcomes.

**Possible investigation steps**

* Review the audit logs for the specific event.action value "v*.compute.networks.delete" to identify the exact time and user account associated with the VPC network deletion.
* Check the event.outcome field to confirm the success of the deletion and correlate it with any other suspicious activities around the same timeframe.
* Investigate the user account or service account that performed the deletion to determine if it was authorized and if there are any signs of compromise or misuse.
* Examine the project and network configurations to assess the impact of the VPC deletion on the organization’s operations and identify any critical resources that were affected.
* Look for any recent changes in IAM roles or permissions that might have allowed unauthorized users to delete the VPC network.
* Cross-reference the deletion event with other security alerts or incidents to identify potential patterns or coordinated attacks.

**False positive analysis**

* Routine maintenance activities may involve the deletion of VPC networks as part of infrastructure updates or reconfigurations. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or tools used for environment cleanup might trigger false positives if they delete VPC networks as part of their operation. Identify these scripts and exclude their actions from triggering alerts by using specific service accounts or tags associated with these tools.
* Development and testing environments often undergo frequent changes, including VPC deletions. Consider excluding these environments from alerts by filtering based on project IDs or environment tags to reduce noise.
* Organizational policy changes might lead to the intentional deletion of VPC networks. Ensure that such policy-driven actions are documented and that the responsible teams are excluded from triggering alerts by using role-based access controls or specific user identifiers.

**Response and remediation**

* Immediately isolate the affected project by restricting network access to prevent further unauthorized deletions or modifications.
* Review the audit logs to identify the source of the deletion request, including the user account and IP address, and verify if it was authorized.
* Recreate the deleted VPC network using the latest backup or configuration snapshot to restore network operations and minimize downtime.
* Implement additional access controls, such as multi-factor authentication and least privilege principles, to prevent unauthorized access to VPC management.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Escalate the incident to Google Cloud Platform support if necessary, especially if there are indications of a broader compromise or if assistance is needed in recovery.
* Enhance monitoring and alerting for VPC-related activities to detect and respond to similar threats more effectively in the future.


## Setup [_setup_1039]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5178]

```js
event.dataset:gcp.audit and event.action:v*.compute.networks.delete and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



