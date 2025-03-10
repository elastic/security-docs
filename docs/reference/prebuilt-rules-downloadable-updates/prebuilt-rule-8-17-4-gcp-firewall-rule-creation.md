---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-firewall-rule-creation.html
---

# GCP Firewall Rule Creation [prebuilt-rule-8-17-4-gcp-firewall-rule-creation]

Identifies when a firewall rule is created in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. These firewall rules can be configured to allow or deny connections to or from virtual machine (VM) instances or specific applications. An adversary may create a new firewall rule in order to weaken their target’s security controls and allow more permissive ingress or egress traffic flows for their benefit.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

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

## Investigation guide [_investigation_guide_4160]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Firewall Rule Creation**

In GCP, firewall rules manage network traffic to and from VPCs and App Engine applications, crucial for maintaining security. Adversaries may exploit this by creating rules that permit unauthorized access, bypassing security measures. The detection rule monitors audit logs for specific actions indicating new rule creation, flagging potential defense evasion attempts to ensure timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:gcp.audit entries to identify the source of the firewall rule creation, focusing on the event.action fields: **.compute.firewalls.insert or google.appengine.**.Firewall.Create*Rule.
* Identify the user or service account responsible for the action by examining the actor information in the audit logs, such as the principalEmail field.
* Determine the network or application affected by the new firewall rule by analyzing the target resources, such as the VPC or App Engine application, to understand the potential impact.
* Assess the rule’s configuration details, including the allowed or denied IP ranges, protocols, and ports, to evaluate if it introduces any security risks or deviates from established security policies.
* Check for any recent changes in permissions or roles assigned to the user or service account involved, which might indicate privilege escalation or misuse.
* Correlate the firewall rule creation event with other security events or alerts in the same timeframe to identify any suspicious patterns or activities that might suggest a coordinated attack.
* Consult with relevant stakeholders or teams to verify if the firewall rule creation was authorized and aligns with current operational requirements or projects.

**False positive analysis**

* Routine administrative actions by authorized personnel can trigger alerts when they create or update firewall rules for legitimate purposes. To manage this, establish a list of known IP addresses or user accounts that frequently perform these actions and create exceptions for them in the detection rule.
* Automated processes or scripts that regularly update firewall configurations as part of normal operations may also cause false positives. Identify these processes and adjust the rule to exclude their specific actions or service accounts.
* Changes made during scheduled maintenance windows might be flagged as suspicious. Implement time-based exceptions to ignore rule creation events during these predefined periods.
* Integration with third-party security tools or services that modify firewall rules for enhanced protection can be mistaken for unauthorized activity. Verify these integrations and whitelist their actions to prevent unnecessary alerts.
* Development and testing environments often require frequent firewall rule changes, which can lead to false positives. Differentiate these environments from production by tagging them appropriately and excluding their events from the detection rule.

**Response and remediation**

* Immediately review the newly created firewall rule to determine its source and intent. Verify if the rule aligns with organizational security policies and intended network configurations.
* Temporarily disable or delete the suspicious firewall rule to prevent unauthorized access while further investigation is conducted.
* Conduct a thorough audit of recent firewall rule changes in the affected GCP project to identify any other unauthorized modifications.
* Isolate affected systems or applications that may have been exposed due to the unauthorized firewall rule to prevent further exploitation.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further action.
* Implement additional monitoring on the affected VPC or App Engine environment to detect any further unauthorized changes or suspicious activities.
* Review and update access controls and permissions for creating and modifying firewall rules to ensure only authorized personnel have the necessary privileges.


## Setup [_setup_1030]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5169]

```js
event.dataset:gcp.audit and event.action:(*.compute.firewalls.insert or google.appengine.*.Firewall.Create*Rule)
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



