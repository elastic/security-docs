---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-lambda-function-policy-updated-to-allow-public-invocation.html
---

# AWS Lambda Function Policy Updated to Allow Public Invocation [prebuilt-rule-8-17-4-aws-lambda-function-policy-updated-to-allow-public-invocation]

Identifies when an AWS Lambda function policy is updated to allow public invocation. This rule specifically looks for the `AddPermission` API call with the `Principal` set to `*` which allows any AWS account to invoke the Lambda function. Adversaries may abuse this permission to create a backdoor in the Lambda function that allows them to execute arbitrary code.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence)
* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/)
* [https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html](https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Lambda
* Use Case: Threat Detection
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4047]

**Triage and analysis**

**Investigating AWS Lambda Function Policy Updated to Allow Public Invocation**

This rule detects when an AWS Lambda function policy is updated to allow public invocation. It specifically looks for the `AddPermission` API call with the `Principal` set to `*`, which allows any AWS account to invoke the Lambda function. Adversaries may abuse this permission to create a backdoor in the Lambda function that allows them to execute arbitrary code. Understanding the context and legitimacy of such changes is crucial to determine if the action is benign or malicious.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific changes made to the Lambda function policy. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the change occurred. Modifications during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the update to allow public invocation aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the change was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the change was unauthorized, update the Lambda function policy to remove the public invocation permission and restore it to its previous state.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive functions or permissions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning Lambda function management and the use of permissions.
* ***Audit Lambda Functions and Policies***: Conduct a comprehensive audit of all Lambda functions and associated policies to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing Lambda functions and securing AWS environments, refer to the [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/welcome.md) and AWS best practices for security. Additionally, consult the following resources for specific details on Lambda persistence techniques: - [AWS Lambda Persistence](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence) - [AWS Lambda Backdoor Function](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/) - [AWS API AddPermission](https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.md)


## Rule query [_rule_query_5064]

```js
event.dataset: aws.cloudtrail
    and event.provider: lambda.amazonaws.com
    and event.outcome: success
    and event.action: AddPermission*
    and aws.cloudtrail.request_parameters: (*lambda\:InvokeFunction* and *principal=\**)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)



