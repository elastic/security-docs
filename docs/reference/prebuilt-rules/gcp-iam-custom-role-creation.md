---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-iam-custom-role-creation.html
---

# GCP IAM Custom Role Creation [gcp-iam-custom-role-creation]

Identifies an Identity and Access Management (IAM) custom role creation in Google Cloud Platform (GCP). Custom roles are user-defined, and allow for the bundling of one or more supported permissions to meet specific needs. Custom roles will not be updated automatically and could lead to privilege creep if not carefully scrutinized.

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

* [https://cloud.google.com/iam/docs/understanding-custom-roles](https://cloud.google.com/iam/docs/understanding-custom-roles)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_356]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP IAM Custom Role Creation**

Google Cloud Platform’s IAM custom roles allow users to define specific permissions tailored to their needs, offering flexibility in access management. However, adversaries can exploit this by creating roles with excessive permissions, leading to privilege escalation. The detection rule monitors audit logs for successful custom role creation events, helping identify potential unauthorized access attempts by flagging unusual role configurations.

**Possible investigation steps**

* Review the audit logs for the specific event.action:google.iam.admin.v*.CreateRole to identify the user or service account responsible for creating the custom role.
* Examine the permissions assigned to the newly created custom role to determine if they are excessive or deviate from standard role configurations.
* Check the event.outcome:success field to confirm the successful creation of the role and cross-reference with any recent changes in IAM policies or permissions.
* Investigate the context around the role creation, such as the time of creation and any associated IP addresses or locations, to identify any unusual patterns or anomalies.
* Assess the necessity and justification for the custom role by consulting with the relevant team or individual who requested its creation, ensuring it aligns with organizational policies and needs.

**False positive analysis**

* Routine administrative actions by authorized personnel can trigger alerts. Regularly review and document legitimate role creation activities to establish a baseline of expected behavior.
* Automated processes or scripts that create roles as part of deployment pipelines may cause false positives. Identify and whitelist these processes to prevent unnecessary alerts.
* Temporary roles created for short-term projects or testing purposes might be flagged. Implement a naming convention for such roles and exclude them from alerts based on this pattern.
* Changes in organizational structure or policy updates can lead to legitimate role creations. Ensure that these changes are communicated to the security team to adjust monitoring rules accordingly.
* Third-party integrations that require custom roles might be misidentified as threats. Maintain an inventory of these integrations and their role requirements to differentiate between legitimate and suspicious activities.

**Response and remediation**

* Immediately review the audit logs to confirm the creation of the custom role and identify the user or service account responsible for the action.
* Revoke the custom role if it is determined to have excessive permissions or if it was created without proper authorization.
* Conduct a thorough review of the permissions assigned to the custom role to ensure they align with the principle of least privilege.
* Notify the security team and relevant stakeholders about the unauthorized role creation for further investigation and potential escalation.
* Implement additional monitoring on the identified user or service account to detect any further suspicious activities.
* Review and update IAM policies to prevent unauthorized role creation, ensuring that only trusted users have the necessary permissions to create custom roles.
* Enhance detection capabilities by setting up alerts for any future custom role creation events, especially those with high-risk permissions.


## Setup [_setup_220]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_388]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



