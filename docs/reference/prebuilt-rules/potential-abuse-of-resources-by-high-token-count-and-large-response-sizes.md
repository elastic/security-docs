---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-abuse-of-resources-by-high-token-count-and-large-response-sizes.html
---

# Potential Abuse of Resources by High Token Count and Large Response Sizes [potential-abuse-of-resources-by-high-token-count-and-large-response-sizes]

Detects potential resource exhaustion or data breach attempts by monitoring for users who consistently generate high input token counts, submit numerous requests, and receive large responses. This behavior could indicate an attempt to overload the system or extract an unusually large amount of data, possibly revealing sensitive information or causing service disruptions.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://atlas.mitre.org/techniques/AML.T0051](https://atlas.mitre.org/techniques/AML.T0051)
* [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [https://www.elastic.co/security-labs/elastic-advances-llm-security](https://www.elastic.co/security-labs/elastic-advances-llm-security)

**Tags**:

* Domain: LLM
* Data Source: AWS Bedrock
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Use Case: Potential Overload
* Use Case: Resource Exhaustion
* Mitre Atlas: LLM04
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_645]

**Triage and analysis**

**Investigating Potential Abuse of Resources by High Token Count and Large Response Sizes**

Amazon Bedrock is AWS’s managed service that enables developers to build and scale generative AI applications using large foundation models (FMs) from top providers.

Bedrock offers a variety of pretrained models from Amazon (such as the Titan series), as well as models from providers like Anthropic, Meta, Cohere, and AI21 Labs.

**Possible investigation steps**

* Identify the user account that used high prompt token counts and whether it should perform this kind of action.
* Investigate large response sizes and the number of requests made by the user account.
* Investigate other alerts associated with the user account during the past 48 hours.
* Consider the time of day. If the user is a human (not a program or script), did the activity take place during a normal time of day?
* Examine the account’s prompts and responses in the last 24 hours.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking Amazon Bedrock model access, prompts generated, and responses to the prompts by the account in the last 24 hours.

**False positive analysis**

* Verify the user account that used high prompt and large response sizes, has a business justification for the heavy usage of the system.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Identify if the attacker is moving laterally and compromising other Amazon Bedrock Services.
* Identify any regulatory or legal ramifications related to this activity.
* Identify potential resource exhaustion and impact on billing.
* Review the permissions assigned to the implicated user group or role behind these requests to ensure they are authorized and expected to access bedrock and ensure that the least privilege principle is being followed.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_411]

**Setup**

This rule requires that guardrails are configured in AWS Bedrock. For more information, see the AWS Bedrock documentation:

[https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.html](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-create.md)


## Rule query [_rule_query_687]

```js
from logs-aws_bedrock.invocation-*
| keep user.id, gen_ai.usage.prompt_tokens, gen_ai.usage.completion_tokens
| stats max_tokens = max(gen_ai.usage.prompt_tokens),
         total_requests = count(*),
         avg_response_size = avg(gen_ai.usage.completion_tokens)
  by user.id
// tokens count depends on specific LLM, as is related to how embeddings are generated.
| where max_tokens > 5000 and total_requests > 10 and avg_response_size > 500
| eval risk_factor = (max_tokens / 1000) * total_requests * (avg_response_size / 500)
| where risk_factor > 10
| sort risk_factor desc
```


