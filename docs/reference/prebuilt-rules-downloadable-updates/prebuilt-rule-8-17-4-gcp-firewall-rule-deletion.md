---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-firewall-rule-deletion.html
---

# GCP Firewall Rule Deletion [prebuilt-rule-8-17-4-gcp-firewall-rule-deletion]

Identifies when a firewall rule is deleted in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. These firewall rules can be configured to allow or deny connections to or from virtual machine (VM) instances or specific applications. An adversary may delete a firewall rule in order to weaken their target’s security controls.

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

* [https://cloud.google.com/vpc/docs/firewalls](https://cloud.google.com/vpc/docs/firewalls)
* [https://cloud.google.com/appengine/docs/standard/python/understanding-firewalls](https://cloud.google.com/appengine/docs/standard/python/understanding-firewalls)

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

## Investigation guide [_investigation_guide_4161]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Firewall Rule Deletion**

In GCP, firewall rules are crucial for controlling network traffic to and from VM instances and applications, ensuring robust security. Adversaries may delete these rules to bypass security measures, facilitating unauthorized access or data exfiltration. The detection rule monitors audit logs for deletion actions, flagging potential defense evasion attempts by identifying specific deletion events in VPC or App Engine environments.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:gcp.audit to confirm the deletion action and gather details such as the timestamp, user identity, and source IP address associated with the event.
* Investigate the event.action field to determine whether the deletion occurred in the VPC or App Engine environment, and identify the specific firewall rule that was deleted.
* Check the user or service account activity around the time of the deletion to identify any suspicious behavior or unauthorized access attempts.
* Assess the impact of the deleted firewall rule by reviewing the network traffic patterns and security posture before and after the deletion.
* Collaborate with the network security team to determine if the deletion was part of a legitimate change management process or if it indicates a potential security incident.

**False positive analysis**

* Routine maintenance or updates by authorized personnel may trigger firewall rule deletions. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or tools used for infrastructure management might delete and recreate firewall rules as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using service accounts or tags associated with these tools.
* Changes in application deployment processes, especially in environments like App Engine, can lead to legitimate firewall rule deletions. Review deployment logs and processes to identify patterns and exclude these from alerts.
* Organizational policy changes that involve restructuring network security may result in bulk deletions of firewall rules. Coordinate with network security teams to understand planned changes and temporarily adjust detection rules during these periods.
* Test environments often have dynamic configurations where firewall rules are frequently added and removed. Exclude specific projects or environments designated for testing from the detection rule to reduce noise.

**Response and remediation**

* Immediately isolate affected VM instances or applications by applying restrictive firewall rules to prevent further unauthorized access or data exfiltration.
* Review audit logs to identify the source of the deletion action, including user accounts and IP addresses involved, and verify if the action was authorized.
* Recreate the deleted firewall rules based on the last known good configuration to restore security controls and prevent unauthorized access.
* Conduct a security review of the affected environment to identify any additional unauthorized changes or indicators of compromise.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data were impacted.
* Implement enhanced monitoring and alerting for firewall rule changes to detect and respond to similar threats more quickly in the future.
* Review and update access controls and permissions for users and service accounts to ensure that only authorized personnel can modify firewall rules.


## Setup [_setup_1031]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5170]

```js
event.dataset:gcp.audit and event.action:(*.compute.firewalls.delete or google.appengine.*.Firewall.Delete*Rule)
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



