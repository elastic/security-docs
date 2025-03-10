---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-virtual-private-cloud-route-creation.html
---

# GCP Virtual Private Cloud Route Creation [gcp-virtual-private-cloud-route-creation]

Identifies when a virtual private cloud (VPC) route is created in Google Cloud Platform (GCP). Google Cloud routes define the paths that network traffic takes from a virtual machine (VM) instance to other destinations. These destinations can be inside a Google VPC network or outside it. An adversary may create a route in order to impact the flow of network traffic in their target’s cloud environment.

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

## Investigation guide [_investigation_guide_374]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Virtual Private Cloud Route Creation**

In Google Cloud Platform, VPC routes dictate the network paths for traffic from VM instances to various destinations, both within and outside the VPC. Adversaries may exploit this by creating routes to reroute or intercept traffic, potentially disrupting or spying on network communications. The detection rule identifies such activities by monitoring specific audit events related to route creation, aiding in the early detection of unauthorized network modifications.

**Possible investigation steps**

* Review the audit logs for the specific event.dataset:gcp.audit and event.action values (v*.compute.routes.insert or "beta.compute.routes.insert") to identify the exact time and user account associated with the route creation.
* Examine the details of the newly created route, including the destination IP range and next hop, to determine if it aligns with expected network configurations or if it appears suspicious.
* Check the IAM permissions and roles of the user account that created the route to assess if they had the necessary privileges and if those privileges are appropriate for their role.
* Investigate any recent changes in the environment that might explain the route creation, such as new deployments or changes in network architecture.
* Correlate the route creation event with other security events or alerts in the same timeframe to identify potential patterns or coordinated activities that could indicate malicious intent.
* Consult with the network or cloud infrastructure team to verify if the route creation was part of an authorized change or if it was unexpected.

**False positive analysis**

* Routine network configuration changes by authorized personnel can trigger alerts. To manage this, maintain a list of known IP addresses and users who frequently make legitimate changes and exclude their activities from triggering alerts.
* Automated deployment tools that create or modify routes as part of their normal operation may cause false positives. Identify these tools and their associated service accounts, then configure exceptions for these accounts in the monitoring system.
* Scheduled maintenance activities often involve creating or updating routes. Document these activities and set temporary exceptions during the maintenance window to prevent unnecessary alerts.
* Integration with third-party services might require route creation. Verify these integrations and whitelist the associated actions to avoid false positives.
* Development and testing environments may have frequent route changes. Consider applying different monitoring thresholds or rules for these environments to reduce noise.

**Response and remediation**

* Immediately isolate the affected VM instances by removing or disabling the suspicious route to prevent further unauthorized traffic redirection.
* Conduct a thorough review of recent route creation activities in the GCP environment to identify any other unauthorized or suspicious routes.
* Revoke any unauthorized access or permissions that may have allowed the adversary to create the route, focusing on IAM roles and service accounts with route creation privileges.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Implement network monitoring and logging to detect any future unauthorized route creation attempts, ensuring that alerts are configured for similar activities.
* Review and update the GCP VPC network security policies to enforce stricter controls on route creation and modification, limiting these actions to trusted administrators only.
* If applicable, report the incident to Google Cloud support for further assistance and to understand if there are any additional security measures or advisories.


## Setup [_setup_238]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_406]

```js
event.dataset:gcp.audit and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
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



