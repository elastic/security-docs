---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-lambda-function-created-or-updated.html
---

# AWS Lambda Function Created or Updated [aws-lambda-function-created-or-updated]

Identifies when an AWS Lambda function is created or updated. AWS Lambda lets you run code without provisioning or managing servers. Adversaries can create or update Lambda functions to execute malicious code, exfiltrate data, or escalate privileges. This is a [building block rule](docs-content://solutions/security/detect-and-alert/about-building-block-rules.md) that does not generate alerts, but signals when a Lambda function is created or updated that matches the rule’s conditions. To generate alerts, create a rule that uses this signal as a building block.

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

* [https://mattslifebytes.com/2023/04/14/from-rebuilds-to-reloads-hacking-aws-lambda-to-enable-instant-code-updates/](https://mattslifebytes.com/2023/04/14/from-rebuilds-to-reloads-hacking-aws-lambda-to-enable-instant-code-updates/)
* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/)
* [https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Lambda
* Use Case: Asset Visibility
* Tactic: Execution
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_63]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "lambda.amazonaws.com"
    and event.outcome: "success"
    and event.action: (CreateFunction* or UpdateFunctionCode*)
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



