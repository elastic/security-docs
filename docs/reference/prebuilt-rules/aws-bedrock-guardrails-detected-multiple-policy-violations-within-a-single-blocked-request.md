---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-bedrock-guardrails-detected-multiple-policy-violations-within-a-single-blocked-request.html
---

# AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request [aws-bedrock-guardrails-detected-multiple-policy-violations-within-a-single-blocked-request]

Identifies multiple violations of AWS Bedrock guardrails within a single request, resulting in a block action, increasing the likelihood of malicious intent. Multiple violations implies that a user may be intentionally attempting to cirvumvent security controls, access sensitive information, or possibly exploit a vulnerability in the system.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.md)
* [https://atlas.mitre.org/techniques/AML.T0051](https://atlas.mitre.org/techniques/AML.T0051)
* [https://atlas.mitre.org/techniques/AML.T0054](https://atlas.mitre.org/techniques/AML.T0054)
* [https://www.elastic.co/security-labs/elastic-advances-llm-security](https://www.elastic.co/security-labs/elastic-advances-llm-security)

**Tags**:

* Domain: LLM
* Data Source: AWS Bedrock
* Data Source: AWS S3
* Resources: Investigation Guide
* Use Case: Policy Violation
* Mitre Atlas: T0051
* Mitre Atlas: T0054

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_6]

**Triage and analysis**

**Investigating AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request**

Amazon Bedrock Guardrail is a set of features within Amazon Bedrock designed to help businesses apply robust safety and privacy controls to their generative AI applications.

It enables users to set guidelines and filters that manage content quality, relevancy, and adherence to responsible AI practices.

Through Guardrail, organizations can define "denied topics" to prevent the model from generating content on specific, undesired subjects, and they can establish thresholds for harmful content categories, including hate speech, violence, or offensive language.

**Possible investigation steps**

* Identify the user account and the user request that caused multiple policy violations and whether it should perform this kind of action.
* Investigate the user activity that might indicate a potential brute force attack.
* Investigate other alerts associated with the user account during the past 48 hours.
* Consider the time of day. If the user is a human (not a program or script), did the activity take place during a normal time of day?
* Examine the account’s prompts and responses in the last 24 hours.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking Amazon Bedrock model access, prompts generated, and responses to the prompts by the account in the last 24 hours.

**False positive analysis**

* Verify the user account that caused multiple policy violations, is not testing any new model deployments or updated compliance policies in Amazon Bedrock guardrails.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Identify if the attacker is moving laterally and compromising other Amazon Bedrock Services.
* Identify any regulatory or legal ramifications related to this activity.
* Review the permissions assigned to the implicated user group or role behind these requests to ensure they are authorized and expected to access bedrock and ensure that the least privilege principle is being followed.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_4]

**Setup**

This rule requires that guardrails are configured in AWS Bedrock. For more information, see the AWS Bedrock documentation:

[https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.md)


## Rule query [_rule_query_6]

```js
from logs-aws_bedrock.invocation-*
| where gen_ai.policy.action == "BLOCKED"
| eval policy_violations = mv_count(gen_ai.policy.name)
| where policy_violations > 1
| keep gen_ai.policy.action, policy_violations, user.id, gen_ai.request.model.id, cloud.account.id, user.id
| stats total_unique_request_violations = count(*) by policy_violations, user.id, gen_ai.request.model.id, cloud.account.id
| sort total_unique_request_violations desc
```


