---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-sts-role-chaining.html
---

# AWS STS Role Chaining [prebuilt-rule-8-17-4-aws-sts-role-chaining]

Identifies role chaining activity. Role chaining is when you use one assumed role to assume a second role through the AWS CLI or API. While this a recognized functionality in AWS, role chaining can be abused for privilege escalation if the subsequent assumed role provides additional privileges. Role chaining can also be used as a persistence mechanism as each AssumeRole action results in a refreshed session token with a 1 hour maximum duration. This rule looks for role chaining activity happening within a single account, to eliminate false positives produced by common cross-account behavior.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.md#id_roles_terms-and-concepts)
* [https://www.uptycs.com/blog/detecting-anomalous-aws-sessions-temporary-credentials](https://www.uptycs.com/blog/detecting-anomalous-aws-sessions-temporary-credentials)
* [https://hackingthe.cloud/aws/post_exploitation/role-chain-juggling/](https://hackingthe.cloud/aws/post_exploitation/role-chain-juggling/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS STS
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4069]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS STS Role Chaining**

AWS Security Token Service (STS) allows temporary, limited-privilege credentials for AWS resources. Role chaining involves using one temporary role to assume another, potentially escalating privileges. Adversaries exploit this by gaining elevated access or persistence. The detection rule identifies such activity by monitoring specific API calls and access patterns within a single account, flagging potential misuse.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the source of the AssumeRole API call by examining the aws.cloudtrail.user_identity.arn field to determine which user or service initiated the role chaining.
* Check the cloud.region field to understand the geographical context of the activity and assess if it aligns with expected operational regions for your organization.
* Investigate the aws.cloudtrail.resources.account_id and aws.cloudtrail.recipient_account_id fields to confirm that the role chaining activity occurred within the same account, as cross-account role chaining is not flagged by this rule.
* Analyze the aws.cloudtrail.user_identity.access_key_id to verify that the access key used is a temporary token starting with "ASIA", indicating the use of temporary credentials.
* Assess the permissions associated with the roles involved in the chaining to determine if the subsequent role provides elevated privileges that could be exploited for privilege escalation or persistence.
* Correlate the timing of the AssumeRole events with other security events or alerts to identify any suspicious patterns or activities that may indicate malicious intent.

**False positive analysis**

* Cross-account role assumptions are common in many AWS environments and can generate false positives. To mitigate this, ensure the rule is configured to only monitor role chaining within a single account, as specified in the rule description.
* Automated processes or applications that frequently assume roles for legitimate purposes may trigger false positives. Identify these processes and create exceptions for their specific access patterns or user identities.
* Scheduled tasks or scripts that use temporary credentials for routine operations might be flagged. Review these tasks and whitelist their access key IDs if they consistently follow a predictable and secure pattern.
* Development and testing environments often involve frequent role assumptions for testing purposes. Exclude these environments from monitoring or adjust the rule to account for their unique access behaviors.
* Regularly review and update the list of exceptions to ensure that only non-threatening behaviors are excluded, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the detected AssumeRole activity to prevent further unauthorized access.
* Conduct a thorough review of the AWS CloudTrail logs to identify any additional suspicious activities or roles assumed using the compromised credentials.
* Isolate the affected AWS resources and accounts to prevent lateral movement and further privilege escalation within the environment.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement stricter IAM policies and role permissions to limit the ability to assume roles unnecessarily, reducing the risk of privilege escalation.
* Enhance monitoring and alerting for AssumeRole activities, especially those involving temporary credentials, to detect similar threats in the future.
* Conduct a post-incident review to identify gaps in security controls and update incident response plans to improve future response efforts.


## Setup [_setup_958]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5086]

```js
from logs-aws.cloudtrail-* metadata _id, _version, _index

// filter for AssumeRole API calls where access key id is a short term token beginning with ASIA
| where event.dataset == "aws.cloudtrail" and event.provider == "sts.amazonaws.com" and event.action == "AssumeRole" and aws.cloudtrail.resources.account_id == aws.cloudtrail.recipient_account_id and aws.cloudtrail.user_identity.access_key_id like "ASIA*"

// keep only the relevant fields
| keep aws.cloudtrail.user_identity.arn, cloud.region, aws.cloudtrail.resources.account_id, aws.cloudtrail.recipient_account_id, aws.cloudtrail.user_identity.access_key_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



