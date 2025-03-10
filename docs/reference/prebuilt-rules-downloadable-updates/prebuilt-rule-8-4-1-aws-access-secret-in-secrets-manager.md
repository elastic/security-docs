---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-access-secret-in-secrets-manager.html
---

# AWS Access Secret in Secrets Manager [prebuilt-rule-8-4-1-aws-access-secret-in-secrets-manager]

An adversary may attempt to access the secrets in secrets manager to steal certificates, credentials, or other sensitive material

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.md)
* [http://detectioninthe.cloud/credential_access/access_secret_in_secrets_manager/](http://detectioninthe.cloud/credential_access/access_secret_in_secrets_manager/)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Data Protection
* Credential Access
* Investigation Guide

**Version**: 103

**Rule authors**:

* Nick Jones
* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2588]

## Triage and analysis

## Investigating AWS Access Secret in Secrets Manager

AWS Secrets Manager is a service that enables the replacement of hardcoded credentials in code, including passwords, with
an API call to Secrets Manager to retrieve the secret programmatically.

This rule looks for the retrieval of credentials using the API `GetSecretValue` action.

### Possible investigation steps

- Identify the account and its role in the environment, and inspect the related policy.
- Identify the applications that should use this account.
- Investigate other alerts associated with the user account during the past 48 hours.
- Investigate abnormal values in the `user_agent.original` field by comparing them with the intended and authorized usage
and historical data. Suspicious user agent values include non-SDK, AWS CLI, custom user agents, etc.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences involving other users.
- Contact the account owner and confirm whether they are aware of this activity.
- Considering the source IP address and geolocation of the user who issued the command:
    - Do they look normal for the calling user?
    - If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source
    IP from an EC2 instance that's not under your control?
    - If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles?
    Are there any other alerts or signs of suspicious activity involving this instance?
- Review IAM permission policies for the user identity and specific secrets accessed.
- Examine the request parameters. These might indicate the source of the program or the nature of its tasks.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- False positives may occur due to the intended usage of the service. Tuning is needed in order to have higher
confidence. Consider adding exceptions — preferably with a combination of user agent and IP address conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Disable or limit the account during the investigation and response.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Assess the criticality of affected services and servers.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify any regulatory or legal ramifications related to this activity.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Rotate secrets or delete API keys as needed to revoke the attacker's access to the environment. Work with
your IT teams to minimize the impact on business operations during these actions.
- Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
- Consider enabling multi-factor authentication for users.
- Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
- Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
- Take the actions needed to return affected systems, data, or services to their normal operational levels.
- Identify the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2979]

```js
event.dataset:aws.cloudtrail and event.provider:secretsmanager.amazonaws.com and event.action:GetSecretValue
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Application Access Token
    * ID: T1528
    * Reference URL: [https://attack.mitre.org/techniques/T1528/](https://attack.mitre.org/techniques/T1528/)



