---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-aws-ec2-deprecated-ami-discovery.html
---

# AWS EC2 Deprecated AMI Discovery [prebuilt-rule-8-17-3-aws-ec2-deprecated-ami-discovery]

Identifies when a user has queried for deprecated Amazon Machine Images (AMIs) in AWS. This may indicate an adversary whom is looking for outdated AMIs that may be vulnerable to exploitation. While deprecated AMIs are not inherently malicious or indicate breach, they may be more susceptible to vulnerabilities and should be investigated for potential security risks.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: AWS EC2
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Discovery

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3910]

**Investigating AWS EC2 Deprecated AMI Discovery**

This rule detects when a user queries AWS for deprecated Amazon Machine Images (AMIs). While deprecated AMIs are not inherently malicious, their use can introduce vulnerabilities or misconfigurations. Adversaries may exploit deprecated AMIs in search of outdated or unpatched systems. Investigating these queries can help identify potential risks or misconfigurations.

**Possible Investigation Steps**

1. ***Identify the User Performing the Query***:

    * Review the `aws.cloudtrail.user_identity.arn` field to determine the AWS user or role making the request.
    * Check `aws.cloudtrail.user_identity.type` and `aws.cloudtrail.user_identity.access_key_id` to verify the type of access (e.g., IAM user, role, or federated identity).
    * Investigate the `related.user` field for additional user context.

2. ***Analyze the Source of the Request***:

    * Review the `source.ip` field to determine the IP address of the source making the request.
    * Check `source.geo` for the geographic location of the IP address.
    * Analyze the `user_agent.original` field to determine the client or tool used (e.g., AWS CLI, SDK).

3. ***Review the Request Details***:

    * Inspect the `aws.cloudtrail.flattened.request_parameters` field for query parameters, such as `includeDeprecated=true`.
    * Confirm that the request explicitly includes deprecated AMIs (`includeDeprecated=true`) and is tied to specific owners via the `ownersSet` field.
    * Verify the `event.action` is `DescribeImages` and the `event.outcome` is `success`.

4. ***Validate the Query Context***:

    * Determine if the request is part of legitimate activity, such as:
    * Security assessments or vulnerability scans.
    * Maintenance or testing of legacy systems.
    * Check if the query aligns with recent changes in the AWS environment, such as new configurations or services.

5. ***Correlate with Other Events***:

    * Investigate additional AWS API calls from the same user or IP address for signs of reconnaissance or exploitation.
    * Review logs for related actions, such as launching instances from deprecated AMIs (`RunInstances` API call).

6. ***Assess Security Risks***:

    * Evaluate the use of deprecated AMIs within your environment and their associated vulnerabilities.
    * Ensure that deprecated AMIs are not being used in production environments or systems exposed to external threats.


**False Positive Analysis**

* ***Legitimate Use***: Users may query for deprecated AMIs for testing or compatibility purposes.
* ***Automated Tools***: Security or compliance tools might query deprecated AMIs as part of regular assessments.
* ***Misconfigured Services***: Legacy systems may rely on deprecated AMIs for compatibility, leading to legitimate queries.

**Response and Remediation**

1. ***Immediate Actions***:

    * Verify the intent of the user querying for deprecated AMIs.
    * Restrict IAM permissions to prevent unauthorized access to deprecated AMIs.

2. ***Mitigation Steps***:

    * Identify and replace deprecated AMIs in use with supported and updated AMIs.
    * Update AWS IAM policies to minimize permissions for querying or using deprecated AMIs.

3. ***Enhance Monitoring***:

    * Enable alerts for future queries involving deprecated AMIs or other unusual API activity.
    * Monitor CloudTrail logs for additional reconnaissance or suspicious behavior.

4. ***Security Audits***:

    * Conduct a review of all AMIs in use across your environment to identify outdated or deprecated images.
    * Remove any deprecated AMIs from production environments and restrict their usage to isolated testing.

5. ***Add Rule Exceptions***:

    * Create exceptions for legitimate use cases or automated tools that query for deprecated AMIs.
    * Document and communicate the exceptions to relevant teams to avoid future alerts.


**Additional Resources**

* [AWS Documentation: AMI Lifecycle Management](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
* [AWS Documentation: Deprecated AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html)


## Rule query [_rule_query_4821]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action: "DescribeImages"
    and event.outcome: "success"
    and aws.cloudtrail.flattened.request_parameters.includeDeprecated: "true"
    and aws.cloudtrail.request_parameters: *owner=*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Infrastructure Discovery
    * ID: T1580
    * Reference URL: [https://attack.mitre.org/techniques/T1580/](https://attack.mitre.org/techniques/T1580/)



