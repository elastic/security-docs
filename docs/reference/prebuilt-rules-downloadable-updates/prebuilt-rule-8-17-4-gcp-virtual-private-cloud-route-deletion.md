---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-virtual-private-cloud-route-deletion.html
---

# GCP Virtual Private Cloud Route Deletion [prebuilt-rule-8-17-4-gcp-virtual-private-cloud-route-deletion]

Identifies when a Virtual Private Cloud (VPC) route is deleted in Google Cloud Platform (GCP). Google Cloud routes define the paths that network traffic takes from a virtual machine (VM) instance to other destinations. These destinations can be inside a Google VPC network or outside it. An adversary may delete a route in order to impact the flow of network traffic in their target’s cloud environment.

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

* [https://cloud.google.com/vpc/docs/routes](https://cloud.google.com/vpc/docs/routes)
* [https://cloud.google.com/vpc/docs/using-routes](https://cloud.google.com/vpc/docs/using-routes)

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

## Investigation guide [_investigation_guide_4171]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Virtual Private Cloud Route Deletion**

In GCP, VPC routes dictate network traffic paths between VM instances and other destinations. Adversaries may delete these routes to disrupt traffic flow, potentially evading defenses or impairing network operations. The detection rule monitors audit logs for successful route deletions, flagging potential misuse by identifying specific actions linked to route removal, thus aiding in timely threat response.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:gcp.audit and event.action:v*.compute.routes.delete to identify the exact time and user account associated with the route deletion.
* Check the event.outcome:success field to confirm the deletion was successful and not an attempted action.
* Investigate the user account or service account that performed the deletion to determine if it was authorized to make such changes, including reviewing recent activity and permissions.
* Assess the impact of the route deletion by identifying which VPC and network traffic paths were affected, and determine if any critical services were disrupted.
* Correlate the route deletion event with other security events or alerts around the same timeframe to identify potential coordinated actions or broader attack patterns.
* Contact the relevant stakeholders or system owners to verify if the route deletion was intentional and part of a planned change or if it was unauthorized.

**False positive analysis**

* Routine maintenance activities by network administrators can trigger route deletions. To manage this, create exceptions for known maintenance windows or specific administrator accounts.
* Automated scripts or tools used for network configuration updates may delete and recreate routes as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts.
* Cloud infrastructure changes during deployment processes might involve temporary route deletions. Document these processes and exclude related events from detection during deployment periods.
* Scheduled network reconfigurations that involve route deletions should be logged and excluded from alerts by correlating with change management records.
* Test environments often undergo frequent network changes, including route deletions. Exclude events from test environments by filtering based on project or environment tags.

**Response and remediation**

* Immediately isolate the affected VPC to prevent further unauthorized network traffic disruptions. This can be done by temporarily disabling external access or applying restrictive firewall rules.
* Review the audit logs to identify the user or service account responsible for the route deletion. Verify if the action was authorized and investigate any anomalies in user behavior or access patterns.
* Restore the deleted route using the latest backup or configuration management tools to re-establish normal network traffic flow. Ensure that the restored route aligns with the intended network architecture.
* Implement additional access controls and monitoring for the affected VPC, such as enabling more granular IAM roles and setting up alerts for any future route modifications.
* Conduct a security review of the affected environment to identify any other potential misconfigurations or vulnerabilities that could be exploited in a similar manner.
* Escalate the incident to the security operations team for further investigation and to determine if the route deletion was part of a larger attack campaign.
* Document the incident, including the root cause analysis and remediation steps taken, to enhance organizational knowledge and improve future incident response efforts.


## Setup [_setup_1041]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5180]

```js
event.dataset:gcp.audit and event.action:v*.compute.routes.delete and event.outcome:success
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



