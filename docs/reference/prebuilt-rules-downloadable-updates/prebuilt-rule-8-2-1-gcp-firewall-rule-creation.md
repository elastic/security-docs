---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-firewall-rule-creation.html
---

# GCP Firewall Rule Creation [prebuilt-rule-8-2-1-gcp-firewall-rule-creation]

Identifies when a firewall rule is created in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. These firewall rules can be configured to allow or deny connections to or from virtual machine (VM) instances or specific applications. An adversary may create a new firewall rule in order to weaken their target’s security controls and allow more permissive ingress or egress traffic flows for their benefit.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/vpc/docs/firewalls](https://cloud.google.com/vpc/docs/firewalls)
* [https://cloud.google.com/appengine/docs/standard/python/understanding-firewalls](https://cloud.google.com/appengine/docs/standard/python/understanding-firewalls)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1929]



## Rule query [_rule_query_2214]

```js
event.dataset:gcp.audit and event.action:(*.compute.firewalls.insert or google.appengine.*.Firewall.Create*Rule)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)



