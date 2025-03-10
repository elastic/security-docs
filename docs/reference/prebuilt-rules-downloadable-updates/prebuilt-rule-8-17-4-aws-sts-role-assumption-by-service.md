---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-sts-role-assumption-by-service.html
---

# AWS STS Role Assumption by Service [prebuilt-rule-8-17-4-aws-sts-role-assumption-by-service]

Identifies when a service has assumed a role in AWS Security Token Service (STS). Services can assume a role to obtain temporary credentials and access AWS resources. Adversaries can use this technique for credential access and privilege escalation. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that identifies when a service assumes a role in AWS Security Token Service (STS) to obtain temporary credentials and access AWS resources. While often legitimate, adversaries may use this technique for unauthorized access, privilege escalation, or lateral movement within an AWS environment.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

**Version**: 210

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4065]

**Triage and analysis**

**Investigating AWS STS Role Assumption by Service**

This rule identifies instances where AWS STS (Security Token Service) is used to assume a role, granting temporary credentials for AWS resource access. While this action is often legitimate, it can be exploited by adversaries to obtain unauthorized access, escalate privileges, or move laterally within an AWS environment.

**Possible Investigation Steps**

* ***Identify the Actor and Assumed Role***:
* ***User Identity***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` fields to determine who initiated the `AssumeRole` action.
* ***Role Assumed***: Check the `aws.cloudtrail.flattened.request_parameters.roleArn` field to confirm the assumed role and ensure it aligns with expected responsibilities.
* ***Session Name***: Observe the `aws.cloudtrail.flattened.request_parameters.roleSessionName` for context on the session’s intended purpose, if available.
* ***Analyze the Role Session and Duration***:
* ***Session Context***: Look at the `aws.cloudtrail.user_identity.session_context.creation_date` to understand when the session began and check if multi-factor authentication (MFA) was used, indicated by the `aws.cloudtrail.user_identity.session_context.mfa_authenticated` field.
* ***Credential Validity***: Examine the `aws.cloudtrail.flattened.request_parameters.durationSeconds` for the credential’s validity period.
* ***Expiration Time***: Verify `aws.cloudtrail.flattened.response_elements.credentials.expiration` to determine when the credentials expire or expired.
* ***Inspect the User Agent for Tooling Identification***:
* ***User Agent Details***: Review the `user_agent.original` field to identify the tool or SDK used for the role assumption. Indicators include:
* ***AWS SDKs (e.g., Boto3)***: Often used in automated workflows or scripts.
* ***AWS CLI***: Suggests command-line access, potentially indicating direct user interaction.
* ***Custom Tooling***: Unusual user agents may signify custom or suspicious tools.
* ***Source IP and Location***: Evaluate the `source.address` and `source.geo` fields to confirm if the access source aligns with typical access locations for your environment.
* ***Contextualize with Related Events***:
* ***Review Event Patterns***: Check surrounding CloudTrail events to see if other actions coincide with this `AssumeRole` activity, such as attempts to access sensitive resources.
* ***Identify High-Volume Exceptions***: Due to the potential volume of `AssumeRole` events, determine common, legitimate `roleArn` values or `user_agent` patterns, and consider adding these as exceptions to reduce noise.
* ***Evaluate the Privilege Level of the Assumed Role***:
* ***Permissions***: Inspect permissions associated with the assumed role to understand its access level.
* ***Authorized Usage***: Confirm whether the role is typically used for administrative purposes and if the assuming entity frequently accesses it as part of regular responsibilities.

**False Positive Analysis**

* ***Automated Workflows and Applications***: Many applications or scheduled tasks may assume roles for standard operations. Check user agents and ARNs for consistency with known workflows.
* ***Routine IAM Policy Actions***: Historical data may reveal if the same user or application assumes this specific role regularly as part of authorized operations.

**Response and Remediation**

* ***Revoke Unauthorized Sessions***: If unauthorized, consider revoking the session by adjusting IAM policies or permissions associated with the assumed role.
* ***Enhance Monitoring and Alerts***: Set up enhanced monitoring for high-risk roles, especially those with elevated privileges.
* ***Manage Exceptions***: Regularly review and manage high-frequency roles and user agent patterns, adding trusted ARNs and user agents to exception lists to minimize alert fatigue.
* ***Incident Response***: If malicious behavior is identified, follow incident response protocols, including containment, investigation, and remediation.

**Additional Information**

For more information on managing and securing AWS STS, refer to the [AWS STS documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.md) and AWS security best practices.


## Rule query [_rule_query_5082]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "sts.amazonaws.com"
    and event.action: "AssumeRole"
    and event.outcome: "success"
    and aws.cloudtrail.user_identity.type: "AWSService"
    and aws.cloudtrail.user_identity.invoked_by: (
          "ec2.amazonaws.com" or
          "lambda.amazonaws.com" or
          "rds.amazonaws.com" or
          "ssm.amazonaws.com" or
          "ecs-tasks.amazonaws.com" or
          "ecs.amazonaws.com" or
          "eks.amazonaws.com" or
          "eks-fargate.amazonaws.com" or
          "codepipeline.amazonaws.com" or
          "codebuild.amazonaws.com" or
          "autoscaling.amazonaws.com")
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



