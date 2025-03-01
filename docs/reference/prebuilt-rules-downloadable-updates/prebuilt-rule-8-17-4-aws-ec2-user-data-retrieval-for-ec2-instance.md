---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-ec2-user-data-retrieval-for-ec2-instance.html
---

# AWS EC2 User Data Retrieval for EC2 Instance [prebuilt-rule-8-17-4-aws-ec2-user-data-retrieval-for-ec2-instance]

Identifies discovery request `DescribeInstanceAttribute` with the attribute userData and instanceId in AWS CloudTrail logs. This may indicate an attempt to retrieve user data from an EC2 instance. Adversaries may use this information to gather sensitive data from the instance such as hardcoded credentials or to identify potential vulnerabilities. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that identifies when `aws.cloudtrail.user_identity.arn` requests the user data for a specific `aws.cloudtrail.flattened.request_parameters.instanceId` from an EC2 instance in the last 14 days.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.md)
* [https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data](https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: Amazon EC2
* Resources: Investigation Guide
* Use Case: Log Auditing
* Tactic: Discovery

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3941]

**Triage and Analysis**

**Investigating AWS EC2 User Data Retrieval for EC2 Instance**

This rule detects requests to retrieve the `userData` attribute of an EC2 instance using the `DescribeInstanceAttribute` API action. The `userData` field can contain sensitive information, such as hardcoded credentials or configuration scripts, that adversaries may exploit for further attacks.

**Possible Investigation Steps**

* ***Identify the Target Instance***:
* ***Instance ID***: Review the `aws.cloudtrail.flattened.request_parameters.instanceId` field to identify the EC2 instance targeted by the request. Confirm whether this instance should expose its `userData` and whether it is associated with sensitive workloads.
* ***Analyze userData***: If possible, retrieve and inspect the `userData` field to identify sensitive information like hardcoded credentials or configuration scripts.
* ***Review User Context***:
* ***User Identity***: Inspect the `aws.cloudtrail.user_identity.arn` field to identify the user or role that executed the `DescribeInstanceAttribute` action. Investigate whether this user typically performs such actions.
* ***Access Patterns***: Validate whether the user or role has the necessary permissions and whether the frequency of this action aligns with expected behavior.
* ***Access Key ID***: Check the `aws.cloudtrail.user_identity.access_key_id` field to determine the key used to make the request as it may be compromised.
* ***Analyze Request Details***:
* ***Parameters***: Verify that the `attribute=userData` parameter was explicitly requested. This indicates intentional access to user data.
* ***Source IP and Geolocation***: Check the `source.address` and `source.geo` fields to validate whether the request originated from a trusted location or network. Unexpected geolocations can indicate adversarial activity.
* ***Review Source Tool***:
* ***User Agent***: Inspect the `user_agent.original` field to determine the tool or client used (e.g., Terraform, AWS CLI). Legitimate automation tools may trigger this activity, but custom or unknown user agents may indicate malicious intent.
* ***Check for Related Activity***:
* ***IAM Changes***: Correlate this event with any IAM changes or temporary credential creation to identify potential privilege escalation attempts.
* ***API Usage***: Look for other unusual API calls (e.g., `RunInstances`, `GetObject`, `AssumeRole`) by the same user or IP to detect lateral movement or data exfiltration attempts.
* ***Validate Intent***:
* ***Permissions and Justification***: Ensure that the user has the least privilege required to perform this action. Investigate whether there is a valid reason for accessing the `userData` field.

**False Positive Analysis**

* ***Automation***: This event is often triggered by legitimate automation tools, such as Terraform or custom scripts, that require access to `userData` during instance initialization.
* ***Maintenance Activity***: Verify whether this event aligns with expected administrative activities, such as debugging or instance configuration updates.

**Response and Remediation**

* ***Revoke Excessive Permissions***: If unauthorized, immediately remove `DescribeInstanceAttribute` permissions from the user or role.
* ***Quarantine the Target Instance***: If malicious behavior is confirmed, isolate the affected EC2 instance to limit further exposure.
* ***Secure User Data***:
* Avoid storing sensitive information, such as credentials, in `userData`. Use AWS Secrets Manager or Parameter Store instead.
* Encrypt user data and ensure only authorized users can decrypt it.
* ***Audit IAM Policies***: Regularly review IAM policies to ensure they adhere to the principle of least privilege.
* ***Monitor and Detect***: Set up additional alerts for unexpected `DescribeInstanceAttribute` calls or other suspicious API activity.

**Additional Information**

For more details on managing EC2 user data securely, refer to the [AWS EC2 User Data Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.md).


## Rule query [_rule_query_4958]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action: "DescribeInstanceAttribute"
    and event.outcome: "success"
    and aws.cloudtrail.request_parameters: (*attribute=userData* and *instanceId*)
    and not aws.cloudtrail.user_identity.invoked_by: (
        "AWS Internal" or
        "cloudformation.amazonaws.com"
    )
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Cloud Instance Metadata API
    * ID: T1552.005
    * Reference URL: [https://attack.mitre.org/techniques/T1552/005/](https://attack.mitre.org/techniques/T1552/005/)



