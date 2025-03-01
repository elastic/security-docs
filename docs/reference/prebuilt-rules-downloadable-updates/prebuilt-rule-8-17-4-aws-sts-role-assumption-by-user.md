---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-sts-role-assumption-by-user.html
---

# AWS STS Role Assumption by User [prebuilt-rule-8-17-4-aws-sts-role-assumption-by-user]

Identifies when a user or role has assumed a role in AWS Security Token Service (STS). Users can assume a role to obtain temporary credentials and access AWS resources. Adversaries can use this technique for credential access and privilege escalation. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that identifies when a service assumes a role in AWS Security Token Service (STS) to obtain temporary credentials and access AWS resources. While often legitimate, adversaries may use this technique for unauthorized access, privilege escalation, or lateral movement within an AWS environment.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS STS
* Resources: Investigation Guide
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4066]

**Triage and analysis**

**Investigating AWS STS Role Assumption by User**

This rule detects when a user assumes a role in AWS Security Token Service (STS), receiving temporary credentials to access AWS resources. While often used for legitimate purposes, this action can be leveraged by adversaries to obtain unauthorized access, escalate privileges, or move laterally within an AWS environment.

**Possible Investigation Steps**

* ***Identify the User and Assumed Role***:
* ***User Identity***: Check `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` for details about the initiator of the `AssumeRole` action.
* ***Role Assumed***: Review `aws.cloudtrail.flattened.request_parameters.roleArn` to confirm the role assumed and ensure it aligns with the user’s standard permissions.
* ***Session Name***: Note `aws.cloudtrail.flattened.request_parameters.roleSessionName` for context on the purpose of the session.
* ***Evaluate Session Context and Credential Duration***:
* ***Session Details***: Look into `aws.cloudtrail.user_identity.session_context.creation_date` for the start of the session and `aws.cloudtrail.user_identity.session_context.mfa_authenticated` to check for MFA usage.
* ***Credential Validity***: Examine `aws.cloudtrail.flattened.request_parameters.durationSeconds` for how long the credentials are valid.
* ***Expiration Time***: Use `aws.cloudtrail.flattened.response_elements.credentials.expiration` to confirm the credential expiration.
* ***Inspect User Agent and Source Information***:
* ***User Agent***: Analyze the `user_agent.original` field to identify if specific tooling or SDKs like AWS CLI, Boto3, or custom agents were used.
* ***Source IP and Geolocation***: Examine `source.address` and `source.geo` fields to determine the origin of the request, confirming if it aligns with expected locations.
* ***Correlate with Related Events***:
* ***Identify Patterns***: Review related CloudTrail events for unusual access patterns, such as resource access or sensitive actions following this `AssumeRole` action.
* ***Filter High-Volume Roles***: If this role or user has a high volume of access, evaluate `roleArn` or `user_agent` values for common patterns and add trusted entities as exceptions.
* ***Review the Privileges of the Assumed Role***:
* ***Permissions***: Examine permissions associated with the `roleArn` to assess its access scope.
* ***Authorized Usage***: Confirm if the role is used frequently for administrative purposes and if this aligns with the user’s regular responsibilities.

**False Positive Analysis**

* ***Automated Processes and Applications***: Applications or scheduled tasks may assume roles regularly for operational purposes. Validate the consistency of the `user_agent` or `roleArn` with known automated workflows.
* ***Standard IAM Policy Usage***: Confirm if the user or application routinely assumes this specific role for normal operations by reviewing historical activity.

**Response and Remediation**

* ***Terminate Unauthorized Sessions***: If the role assumption is deemed unauthorized, revoke the session by modifying IAM policies or the permissions associated with the assumed role.
* ***Strengthen Monitoring and Alerts***: Implement additional monitoring for specific high-risk roles, especially those with elevated permissions.
* ***Regularly Manage Exceptions***: Regularly review high-volume roles and user agent patterns to refine alerts, minimizing noise by adding trusted patterns as exceptions.
* ***Incident Response***: If confirmed as malicious, follow incident response protocols for containment, investigation, and remediation.

**Additional Information**

For more details on managing and securing AWS STS in your environment, refer to the [AWS STS documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.md).


## Rule query [_rule_query_5083]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "sts.amazonaws.com"
    and event.action: "AssumeRole"
    and event.outcome: "success"
    and aws.cloudtrail.user_identity.type: ("AssumedRole" or "IAMUser")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)



