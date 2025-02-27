---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-systems-manager-securestring-parameter-request-with-decryption-flag.html
---

# AWS Systems Manager SecureString Parameter Request with Decryption Flag [prebuilt-rule-8-17-4-aws-systems-manager-securestring-parameter-request-with-decryption-flag]

Detects the first occurrence of a user identity accessing AWS Systems Manager (SSM) SecureString parameters using the GetParameter or GetParameters API actions with credentials in the request parameters. This could indicate that the user is accessing sensitive information. This rule detects when a user accesses a SecureString parameter with the `withDecryption` parameter set to true. This is a [NewTerms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that detects the first occurrence of a specific AWS ARN accessing SecureString parameters with decryption within the last 10 days.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/vsts/latest/userguide/systemsmanager-getparameter.html](https://docs.aws.amazon.com/vsts/latest/userguide/systemsmanager-getparameter.md)
* [https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Systems Manager
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3985]

**Triage and analysis**

**Investigating AWS Systems Manager SecureString Parameter Request with Decryption Flag**

This rule detects when an AWS resource accesses SecureString parameters within AWS Systems Manager (SSM) with the decryption flag set to true. SecureStrings are encrypted using a KMS key, and accessing these with decryption can indicate attempts to access sensitive data.

Adversaries may target SecureStrings to retrieve sensitive information such as encryption keys, passwords, and other credentials that are stored securely. Accessing these parameters with decryption enabled is particularly concerning because it implies the adversary is attempting to bypass the encryption to obtain plain text values that can be immediately used or exfiltrated. This behavior might be part of a larger attack strategy aimed at escalating privileges or moving laterally within an environment to access protected data or critical infrastructure.

**Possible Investigation Steps**

* ***Review the Access Event***: Identify the specific API call (`GetParameter` or `GetParameters`) that triggered the rule. Examine the `request_parameters` for `withDecryption` set to true and the name of the accessed parameter.
* ***Verify User Identity and Access Context***: Check the `user_identity` details to understand who accessed the parameter and their role within the organization. This includes checking the ARN and access key ID to determine if the access was authorized.
* ***User ID***: Review the `user.id` field to identify the specific user or role that initiated the API call. Note that the ARN associated may be an assumed role and may not directly correspond to a human user.
* ***Contextualize with User Behavior***: Assess whether the access pattern fits the user’s normal behavior or job responsibilities. Investigate any out-of-pattern activities around the time of the event.
* ***Analyze Geographic and IP Context***: Using the `source.ip` and `source.geo` information, verify if the request came from a trusted location or if there are any anomalies that suggest a compromised account.
* ***Inspect Related CloudTrail Events***: Look for other related events in CloudTrail to see if there was unusual activity before or after this event, such as unusual login attempts, changes to permissions, or other API calls that could indicate broader unauthorized actions.

**False Positive Analysis**

* ***Legitimate Administrative Use***: Verify if the decryption of SecureString parameters is a common practice for the user’s role, particularly if used in automation scripts or deployment processes like those involving Terraform or similar tools.
* ***Authorized Access***: Ensure that the user or role has a legitimate reason to access the SecureString parameters and that the access is part of their expected job responsibilities.

**Response and Remediation**

* ***Immediate Verification***: Contact the user or team responsible for the API call to verify their intent and authorization.
* ***Review and Revise Permissions***: If the access was unauthorized, review the permissions assigned to the user or role to ensure they align with the principle of least privilege.
* ***Audit Parameter Access Policies***: Ensure that policies governing access to SecureString parameters are strict and audit logs are enabled to track access with decryption.
* ***Incident Response***: If suspicious activity is confirmed, follow through with your organization’s incident response plan to mitigate any potential security issues.
* ***Enhanced Monitoring and Alerting***: Strengthen monitoring rules to detect unusual accesses to SecureString parameters, especially those that involve decryption.

**Additional Information**

This rule focuses solely on SecureStrings in AWS Systems Manager (SSM) parameters. SecureStrings are encrypted using an AWS Key Management Service (KMS) key. When a user accesses a SecureString parameter, they can specify whether the parameter should be decrypted. If the user specifies that the parameter should be decrypted, the decrypted value is returned in the response.


## Setup [_setup_919]

This rule requires that AWS CloudTrail logs are ingested into the Elastic Stack. Ensure that the AWS integration is properly configured to collect AWS CloudTrail logs. This rule also requires event logging for AWS Systems Manager (SSM) API actions which can be enabled in CloudTrail’s data events settings.


## Rule query [_rule_query_5002]

```js
event.dataset: aws.cloudtrail
    and event.provider: "ssm.amazonaws.com"
    and event.action: (GetParameters or GetParameter)
    and event.outcome: success
    and aws.cloudtrail.flattened.request_parameters.withDecryption: true
    and not source.address: (
        "cloudformation.amazonaws.com" or
        "servicecatalog.amazonaws.com"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Cloud Secrets Management Stores
    * ID: T1555.006
    * Reference URL: [https://attack.mitre.org/techniques/T1555/006/](https://attack.mitre.org/techniques/T1555/006/)



