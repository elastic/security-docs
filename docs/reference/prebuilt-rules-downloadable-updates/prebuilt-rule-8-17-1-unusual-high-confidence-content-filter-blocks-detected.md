---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-unusual-high-confidence-content-filter-blocks-detected.html
---

# Unusual High Confidence Content Filter Blocks Detected [prebuilt-rule-8-17-1-unusual-high-confidence-content-filter-blocks-detected]

Detects repeated high-confidence *BLOCKED* actions coupled with specific *Content Filter* policy violation having codes such as *MISCONDUCT*, *HATE*, *SEXUAL*, INSULTS', *PROMPT_ATTACK*, *VIOLENCE* indicating persistent misuse or attempts to probe the model’s ethical boundaries.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

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
* Use Case: Policy Violation
* Mitre Atlas: T0051
* Mitre Atlas: T0054

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3892]

**Triage and analysis**

**Investigating Amazon Bedrock Guardrail High Confidence Content Filter Blocks.**

Amazon Bedrock Guardrail is a set of features within Amazon Bedrock designed to help businesses apply robust safety and privacy controls to their generative AI applications.

It enables users to set guidelines and filters that manage content quality, relevancy, and adherence to responsible AI practices.

Through Guardrail, organizations can enable Content filter for Hate, Insults, Sexual Violence and Misconduct along with Prompt Attack filters prompts to prevent the model from generating content on specific, undesired subjects, and they can establish thresholds for harmful content categories.

**Possible investigation steps**

* Identify the user account whose prompts caused high confidence content filter blocks and whether it should perform this kind of action.
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


## Setup [_setup_769]

**Setup**

This rule requires that guardrails are configured in AWS Bedrock. For more information, see the AWS Bedrock documentation:

[https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.md)


## Rule query [_rule_query_4784]

```js
from logs-aws_bedrock.invocation-*
| MV_EXPAND gen_ai.compliance.violation_code
| MV_EXPAND gen_ai.policy.confidence
| MV_EXPAND gen_ai.policy.name
| where gen_ai.policy.action == "BLOCKED" and gen_ai.policy.name == "content_policy" and gen_ai.policy.confidence LIKE "HIGH" and gen_ai.compliance.violation_code IN ("HATE", "MISCONDUCT", "SEXUAL", "INSULTS", "PROMPT_ATTACK", "VIOLENCE")
| keep user.id, gen_ai.compliance.violation_code
| stats block_count_per_violation = count() by user.id, gen_ai.compliance.violation_code
| SORT block_count_per_violation DESC
| keep user.id, gen_ai.compliance.violation_code, block_count_per_violation
| STATS violation_count = SUM(block_count_per_violation) by user.id
| WHERE violation_count > 5
| SORT violation_count DESC
```


