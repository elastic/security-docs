---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-time-seen-aws-secret-value-accessed-in-secrets-manager.html
---

# First Time Seen AWS Secret Value Accessed in Secrets Manager [first-time-seen-aws-secret-value-accessed-in-secrets-manager]

An adversary with access to a compromised AWS service such as an EC2 instance, Lambda function, or other service may attempt to leverage the compromised service to access secrets in AWS Secrets Manager. This rule looks for the first time a specific user identity has programmatically retrieved a secret value from Secrets Manager using the `GetSecretValue` or `BatchGetSecretValue` actions. This rule assumes that AWS services such as Lambda functions and EC2 instances are setup with IAM role’s assigned that have the necessary permissions to access the secrets in Secrets Manager. An adversary with access to a compromised AWS service such as an EC2 instance, Lambda function, or other service would rely on the compromised service’s IAM role to access the secrets in Secrets Manager.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.md)
* [https://detectioninthe.cloud/ttps/credential_access/access_secret_in_secrets_manager/](https://detectioninthe.cloud/ttps/credential_access/access_secret_in_secrets_manager/)
* [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.md)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-secrets-manager-enum](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-secrets-manager-enum)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Secrets Manager
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Nick Jones
* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_344]

**Triage and analysis**

**Investigating First Time Seen AWS Secret Value Accessed in Secrets Manager**

AWS Secrets Manager is a service that enables the replacement of hardcoded credentials in code, including passwords, with an API call to Secrets Manager to retrieve the secret programmatically.

This rule looks for the retrieval of credentials using `GetSecretValue` action in Secrets Manager programmatically. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule indicating this is the first time a specific user identity has successfuly retrieved a specific secret value from Secrets Manager within the last 15 days.

**Possible investigation steps**

* Identify the account and its role in the environment, and inspect the related policy.
* Identify the applications that should use this account.
* Investigate other alerts associated with the user account during the past 48 hours.
* Investigate abnormal values in the `user_agent.original` field by comparing them with the intended and authorized usage and historical data. Suspicious user agent values include non-SDK, AWS CLI, custom user agents, etc.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences involving other users.
* Contact the account owner and confirm whether they are aware of this activity.
* Considering the source IP address and geolocation of the user who issued the command:
* Do they look normal for the calling user?
* If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source IP from an EC2 instance that’s not under your control?
* If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
* Review IAM permission policies for the user identity and specific secrets accessed.
* Examine the request parameters. These might indicate the source of the program or the nature of its tasks.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

**False positive analysis**

* Review `user.id` values for expected ARNs. If this is an expected behavior, consider adding exceptions to the rule.
* False positives may occur due to the intended usage of the service. Tuning is needed in order to have higher confidence. Consider adding exceptions — preferably with a combination of user agent and IP address conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Assess the criticality of affected services and servers.
* Work with your IT team to identify and minimize the impact on users.
* Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
* Identify any regulatory or legal ramifications related to this activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Rotate secrets or delete API keys as needed to revoke the attacker’s access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
* Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
* Consider enabling multi-factor authentication for users.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
* Take the actions needed to return affected systems, data, or services to their normal operational levels.
* Identify the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_376]

```js
event.dataset:aws.cloudtrail and event.provider:secretsmanager.amazonaws.com and
    event.action: (GetSecretValue or BatchGetSecretValue) and event.outcome:success and
    not user_agent.name: ("Chrome" or "Firefox" or "Safari" or "Edge" or "Brave" or "Opera")
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



