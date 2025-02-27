---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/web-application-suspicious-activity-post-request-declined.html
---

# Web Application Suspicious Activity: POST Request Declined [web-application-suspicious-activity-post-request-declined]

A POST request to a web application returned a 403 response, which indicates the web application declined to process the request because the action requested was not allowed.

**Rule type**: query

**Rule indices**:

* apm-**-transaction**
* traces-apm*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://en.wikipedia.org/wiki/HTTP_403](https://en.wikipedia.org/wiki/HTTP_403)

**Tags**:

* Data Source: APM
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1189]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Web Application Suspicious Activity: POST Request Declined**

Web applications often use POST requests to handle data submissions securely. However, adversaries may exploit this by attempting unauthorized actions, triggering a 403 error when access is denied. The detection rule identifies such anomalies by flagging POST requests that receive a 403 response, indicating potential misuse or probing attempts, thus aiding in early threat detection.

**Possible investigation steps**

* Review the source IP address and user agent associated with the POST request to identify any patterns or known malicious actors.
* Examine the URL or endpoint targeted by the POST request to determine if it is a sensitive or restricted resource.
* Check the timestamp of the request to see if it coincides with other suspicious activities or known attack patterns.
* Analyze the frequency and volume of similar 403 POST requests from the same source to assess if this is part of a larger probing or attack attempt.
* Investigate any recent changes or updates to the web application that might have inadvertently triggered legitimate requests to be denied.

**False positive analysis**

* Legitimate API interactions may trigger 403 responses if the API endpoint is accessed without proper authentication or authorization. Review API access logs to identify and whitelist known applications or users that frequently interact with the API.
* Web application firewalls (WAFs) might block certain POST requests due to predefined security rules, resulting in 403 errors. Analyze WAF logs to determine if specific rules are causing false positives and adjust the ruleset accordingly.
* Automated scripts or bots performing routine tasks might inadvertently trigger 403 responses. Identify these scripts and ensure they are configured with the necessary permissions or exclude their IP addresses from the detection rule.
* User error, such as incorrect form submissions or missing required fields, can lead to 403 responses. Educate users on proper form usage and consider implementing client-side validation to reduce these occurrences.
* Maintenance or configuration changes in the web application might temporarily cause 403 errors. Coordinate with the development or operations team to understand scheduled changes and adjust monitoring rules during these periods.

**Response and remediation**

* Immediately review the logs associated with the 403 POST requests to identify the source IP addresses and user agents involved. Block any suspicious IP addresses at the firewall or web application firewall (WAF) to prevent further unauthorized attempts.
* Conduct a thorough review of the web application’s access control policies and permissions to ensure that they are correctly configured to prevent unauthorized actions.
* Check for any recent changes or updates to the web application that might have inadvertently altered access controls or introduced vulnerabilities, and roll back or patch as necessary.
* Notify the security operations team to monitor for any additional suspicious activity from the identified IP addresses or similar patterns, and escalate to incident response if further malicious activity is detected.
* Implement additional logging and monitoring for POST requests that result in 403 responses to enhance detection capabilities and gather more context for future incidents.
* Review and update the web application firewall (WAF) rules to better detect and block unauthorized POST requests, ensuring that legitimate traffic is not affected.
* If applicable, engage with the development team to conduct a security review of the application code to identify and fix any potential vulnerabilities that could be exploited by attackers.


## Rule query [_rule_query_1215]

```js
http.response.status_code:403 and http.request.method:post
```


