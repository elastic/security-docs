---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-iam-roles-anywhere-profile-creation.html
---

# AWS IAM Roles Anywhere Profile Creation [aws-iam-roles-anywhere-profile-creation]

Identifies the creation of an AWS Roles Anywhere profile. AWS Roles Anywhere is a feature that allows you to use AWS Identity and Access Management (IAM) profiles to manage access to your AWS resources from any location via trusted anchors. This rule detects the creation of a profile that can be assumed from any service. Adversaries may create profiles tied to overly permissive roles to maintain access to AWS resources. Ensure that the profile creation is expected and that the trust policy is configured securely.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.md)
* [https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-iam-roles-anywhere-trust-anchor-created/](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-iam-roles-anywhere-trust-anchor-created/)
* [https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/](https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/)
* [https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateProfile.html](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateProfile.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_55]

**Triage and analysis**

**Investigating AWS IAM Roles Anywhere Profile Creation**

This rule detects the creation of an AWS Roles Anywhere profile. AWS Roles Anywhere allows you to use AWS Identity and Access Management (IAM) profiles to manage access to your AWS resources from any location via trusted anchors. Adversaries may create profiles tied to overly permissive roles to maintain access to AWS resources. It is crucial to ensure that the profile creation is expected and that the trust policy is configured securely.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who created the profile. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific details of the profile creation. Look for any unusual parameters or overly permissive roles that could suggest unauthorized or malicious activity.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the location and origin of the request. Ensure the request originated from a known and trusted location.
* ***Check the Created Profile’s Permissions***: Review the `roleArns` associated with the created profile. Verify that the roles are appropriate for the user’s intended actions and do not grant excessive permissions.
* ***Verify the Profile’s Configuration***: Ensure that the profile’s `durationSeconds`, `enabled`, and `tags` are configured according to your organization’s security policies. Pay particular attention to any configuration that might allow prolonged access or concealment of activity.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the profile creation aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the profile creation was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the profile creation was unauthorized, disable or delete the created profile and review the associated roles and permissions for any potential misuse.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive roles or unexpected locations.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning profile and role management and the risks of unauthorized profile creation.
* ***Audit IAM Policies and Permissions***: Conduct a comprehensive audit of all IAM policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing AWS IAM Roles Anywhere profiles and securing AWS environments, refer to the [AWS Roles Anywhere documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.md) and AWS best practices for security. Additionally, consult the following resources for specific details on profile management and potential abuse: - [AWS IAM Roles Anywhere Profile Creation API Reference](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateProfile.md) - [Ermetic Blog - Managing Third Party Access](https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/)


## Rule query [_rule_query_57]

```js
event.dataset:aws.cloudtrail
    and event.provider: rolesanywhere.amazonaws.com
    and event.action: CreateProfile
    and event.outcome: success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)



