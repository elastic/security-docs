---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-aws-s3-unauthenticated-bucket-access-by-rare-source.html
---

# AWS S3 Unauthenticated Bucket Access by Rare Source [prebuilt-rule-8-17-3-aws-s3-unauthenticated-bucket-access-by-rare-source]

Identifies AWS CloudTrail events where an unauthenticated source is attempting to access an S3 bucket. This activity may indicate a misconfigured S3 bucket policy that allows public access to the bucket, potentially exposing sensitive data to unauthorized users. Adversaries can specify `--no-sign-request` in the AWS CLI to retrieve objects from an S3 bucket without authentication. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule, which means it will only trigger once for each unique value of the `source.address` field that has not been seen making this API request within the last 7 days. This field contains the IP address of the source making the request.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: Amazon S3
* Use Case: Asset Visibility
* Resources: Investigation Guide
* Tactic: Collection

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3908]

**Investigating AWS S3 Unauthenticated Bucket Access by Rare Source**

This rule detects requests to an AWS S3 bucket by an unauthenticated source, which could indicate a misconfigured bucket policy allowing public access. Adversaries can exploit this misconfiguration by using tools or AWS CLI options like `--no-sign-request` to access bucket contents.

The rule triggers when an unauthenticated IP address retrieves an object, and that IP has not been seen in the last 7 days.

**Possible Investigation Steps**

1. ***Identify the Source of the Request***:

    * Review the `source.address` field to determine the IP address of the request source.
    * Check `source.geo` fields for geographic details of the originating IP address.
    * Analyze the `user_agent.original` field to identify the client or tool used (e.g., `Python Requests`, `aws-cli`, browser).

2. ***Review the Accessed Bucket and Object***:

    * Analyze the `aws.cloudtrail.resources.arn` field to identify the S3 bucket and object being accessed.
    * Inspect `aws.cloudtrail.request_parameters` for bucket name and object key to determine which file was retrieved.
    * Review the `even.action` field to identify which API call was made (e.g., `GetObject`, `ListObjects`, `PutObject`, `ListBucket`).

3. ***Validate the Source IP and Context***:

    * Determine if the IP address (`source.address`) has any prior activity in your environment.
    * Correlate the IP with threat intelligence or blocklist databases to check for malicious indicators.
    * Review CloudTrail logs for other activities originating from the same IP.

4. ***Analyze the S3 Bucket Configuration***:

    * Review the S3 bucket’s Access Control List (ACL) and bucket policy to check for misconfigurations allowing public or unauthenticated access.
    * Look for overly permissive settings, such as `Principal: *` or `Effect: Allow` rules that expose the bucket.

5. ***Investigate Additional Activity***:

    * Check if there are subsequent actions, such as:
    * ***Additional `GetObject` API calls***: Indicating further data exfiltration.
    * ***ListObjects requests***: Attempting to enumerate the bucket’s contents.
    * Correlate events within the same timeframe to identify related suspicious activity.

6. ***Assess the Data Exposed***:

    * Identify the retrieved object(s) and analyze their content to assess potential data exposure.
    * Determine if the file contains sensitive information, such as credentials, intellectual property, or PII.


**False Positive Analysis**

* ***Public Buckets by Design***: Some S3 buckets may intentionally allow public access. Verify with the bucket owner if the access was expected.
* ***Automated Tools***: Security scanners or legitimate services may generate `GetObject` events to validate bucket configurations.

**Response and Remediation**

1. ***Immediate Action***:

    * Restrict or remove public access to the affected S3 bucket.
    * Update the bucket policy to ensure access is restricted to trusted principals.
    * Enable ***S3 Block Public Access*** settings to prevent unintended public access.

2. ***Monitoring and Detection***:

    * Enable detailed logging and monitoring for all S3 bucket activities.
    * Configure real-time alerts for unauthenticated `GetObject` or `ListObjects` events on sensitive S3 buckets.

3. ***Security Audits***:

    * Regularly audit S3 bucket policies and ACLs to ensure they adhere to AWS security best practices.
    * Use AWS tools like ***Trusted Advisor*** or ***Access Analyzer*** to identify and address misconfigurations.

4. ***Investigate for Data Exfiltration***:

    * Analyze historical CloudTrail logs to determine if other sensitive files were accessed or exfiltrated.
    * Assess the scope of the exposure and initiate further response if sensitive data was compromised.


**Additional Resources**

* [AWS Documentation: S3 Bucket Policy Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.md)
* [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.md)


## Rule query [_rule_query_4819]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "s3.amazonaws.com"
    and event.action: (
        "GetObject" or
        "PutObject" or
        "ListObjects" or
        "DeleteObject" or
        "ListBucket")
    and event.outcome: "success"
    and aws.cloudtrail.user_identity.type: ("AWSAccount" or "Unknown")
    and cloud.account.id: "anonymous"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Storage Object Discovery
    * ID: T1619
    * Reference URL: [https://attack.mitre.org/techniques/T1619/](https://attack.mitre.org/techniques/T1619/)

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



