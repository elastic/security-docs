---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-firewall-rule-modification.html
---

# GCP Firewall Rule Modification [prebuilt-rule-8-17-4-gcp-firewall-rule-modification]

Identifies when a firewall rule is modified in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. These firewall rules can be modified to allow or deny connections to or from virtual machine (VM) instances or specific applications. An adversary may modify an existing firewall rule in order to weaken their target’s security controls and allow more permissive ingress or egress traffic flows for their benefit.

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

## Investigation guide [_investigation_guide_4162]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Firewall Rule Modification**

In GCP, firewall rules regulate network traffic to and from VPCs and App Engine applications, crucial for maintaining security. Adversaries may alter these rules to weaken defenses, enabling unauthorized access or data exfiltration. The detection rule monitors audit logs for modifications to firewall rules, identifying potential defense evasion attempts by flagging suspicious changes in network configurations.

**Possible investigation steps**

* Review the audit logs for entries with the event.dataset field set to gcp.audit to confirm the source of the alert.
* Examine the event.action field for values such as **.compute.firewalls.patch or google.appengine.**.Firewall.Update*Rule to identify the specific type of firewall rule modification.
* Identify the user or service account responsible for the modification by checking the actor information in the audit logs.
* Assess the changes made to the firewall rule, including the before and after states, to determine if the modification allows more permissive ingress or egress traffic.
* Investigate the context of the modification by reviewing related activities in the audit logs around the same time to identify any suspicious patterns or sequences of actions.
* Check for any recent security incidents or alerts involving the affected VPC or App Engine application to understand potential motives or impacts of the rule change.
* If unauthorized or suspicious activity is confirmed, initiate incident response procedures to mitigate any potential security risks.

**False positive analysis**

* Routine updates or maintenance activities by authorized personnel can trigger alerts. To manage this, create exceptions for known IP addresses or user accounts that regularly perform these tasks.
* Automated scripts or tools used for infrastructure management might modify firewall rules as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific service accounts or tags.
* Changes made during scheduled maintenance windows can be considered non-threatening. Implement time-based exceptions to ignore modifications during these periods.
* Modifications related to scaling operations in App Engine or VPCs might be legitimate. Review and whitelist specific actions associated with scaling events to prevent unnecessary alerts.
* Regular audits or compliance checks might involve temporary rule changes. Document these activities and exclude them from detection by correlating with audit logs or change management records.

**Response and remediation**

* Immediately isolate the affected VPC or App Engine application by applying a restrictive firewall rule to prevent further unauthorized access or data exfiltration.
* Review the audit logs to identify the source of the modification, including user accounts and IP addresses involved, and revoke any suspicious credentials or access.
* Restore the firewall rule to its previous secure state using backup configurations or documented baselines to ensure the network is protected.
* Conduct a thorough security assessment of the affected environment to identify any additional unauthorized changes or indicators of compromise.
* Notify the security operations team and relevant stakeholders about the incident, providing details of the modification and actions taken.
* Implement enhanced monitoring and alerting for future firewall rule changes to detect and respond to similar threats more quickly.
* Consider engaging with Google Cloud support or a third-party security expert if the incident scope is beyond internal capabilities or if further expertise is required.


## Setup [_setup_1032]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5171]

```js
event.dataset:gcp.audit and event.action:(*.compute.firewalls.patch or google.appengine.*.Firewall.Update*Rule)
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



