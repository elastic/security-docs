---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-unusual-high-word-policy-blocks-detected.html
---

# Unusual High Word Policy Blocks Detected [prebuilt-rule-8-17-1-unusual-high-word-policy-blocks-detected]

Detects repeated compliance violation *BLOCKED* actions coupled with specific policy name such as *word_policy*, indicating persistent misuse or attempts to probe the model’s denied topics.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html)
* [https://atlas.mitre.org/techniques/AML.T0051](https://atlas.mitre.org/techniques/AML.T0051)
* [https://atlas.mitre.org/techniques/AML.T0054](https://atlas.mitre.org/techniques/AML.T0054)
* [https://www.elastic.co/security-labs/elastic-advances-llm-security](https://www.elastic.co/security-labs/elastic-advances-llm-security)

**Tags**:

* Domain: LLM
* Data Source: AWS Bedrock
* Data Source: AWS S3
* Use Case: Policy Violation
* Mitre Atlas: T0051
* Mitre Atlas: T0054

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3890]

**Triage and analysis**

**Investigating Amazon Bedrock Guardrail High Word Policy Blocks.**

Amazon Bedrock Guardrail is a set of features within Amazon Bedrock designed to help businesses apply robust safety and privacy controls to their generative AI applications.

It enables users to set guidelines and filters that manage content quality, relevancy, and adherence to responsible AI practices.

Through Guardrail, organizations can define "word filters" to prevent the model from generating content on profanity, undesired subjects, and they can establish thresholds for harmful content categories, including hate speech, violence, or offensive language.

**Possible investigation steps**

* Identify the user account whose prompts contained profanity and whether it should perform this kind of action.
* Investigate other alerts associated with the user account during the past 48 hours.
* Consider the time of day. If the user is a human (not a program or script), did the activity take place during a normal time of day?
* Examine the account’s prompts and responses in the last 24 hours.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking Amazon Bedrock model access, prompts generated, and responses to the prompts by the account in the last 24 hours.

**False positive analysis**

* Verify the user account that queried denied topics, is not testing any new model deployments or updated compliance policies in Amazon Bedrock guardrails.

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


## Setup [_setup_768]

**Setup**

This rule requires that guardrails are configured in AWS Bedrock. For more information, see the AWS Bedrock documentation:

[https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.html)


## Rule query [_rule_query_4782]

```js
from logs-aws_bedrock.invocation-*
| MV_EXPAND gen_ai.policy.name
| where gen_ai.policy.action == "BLOCKED" and gen_ai.compliance.violation_detected == "true" and gen_ai.policy.name == "word_policy"
| keep user.id
| stats profanity_words= count() by user.id
| where profanity_words > 5
| sort profanity_words desc
```


