---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-lambda-layer-added-to-existing-function.html
---

# AWS Lambda Layer Added to Existing Function [aws-lambda-layer-added-to-existing-function]

Identifies when an Lambda Layer is added to an existing Lambda function. AWS layers are a way to share code and data across multiple functions. By adding a layer to an existing function, an attacker can persist or execute code in the context of the function.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence)
* [https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.html](https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.md)
* [https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Lambda
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_62]

**Triage and analysis**

**Investigating AWS Lambda Layer Added to Existing Function**

This rule detects when a Lambda layer is added to an existing Lambda function. AWS Lambda layers are a mechanism for sharing code and data across multiple functions. By adding a layer to an existing function, an attacker can persist or execute code in the context of the function. Understanding the context and legitimacy of such changes is crucial to determine if the action is benign or malicious.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific layer added to the Lambda function. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the change occurred. Modifications during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the addition of the Lambda layer aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the change was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the change was unauthorized, remove the added layer from the Lambda function to mitigate any unintended code execution or persistence.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive functions or layers.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning Lambda function management and the use of layers.
* ***Audit Lambda Functions and Policies***: Conduct a comprehensive audit of all Lambda functions and associated policies to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing Lambda functions and securing AWS environments, refer to the [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/welcome.md) and AWS best practices for security. Additionally, consult the following resources for specific details on Lambda layers and persistence techniques: - [AWS Lambda Layers Persistence](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence) - [AWS API PublishLayerVersion](https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.md) - [AWS API UpdateFunctionConfiguration](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.md)


## Rule query [_rule_query_65]

```js
event.dataset: aws.cloudtrail
    and event.provider: lambda.amazonaws.com
    and event.outcome: success
    and event.action: (PublishLayerVersion* or UpdateFunctionConfiguration)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Serverless Execution
    * ID: T1648
    * Reference URL: [https://attack.mitre.org/techniques/T1648/](https://attack.mitre.org/techniques/T1648/)



