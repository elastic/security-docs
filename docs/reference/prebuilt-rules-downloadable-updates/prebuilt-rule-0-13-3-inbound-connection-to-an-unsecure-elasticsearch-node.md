---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-3-inbound-connection-to-an-unsecure-elasticsearch-node.html
---

# Inbound Connection to an Unsecure Elasticsearch Node [prebuilt-rule-0-13-3-inbound-connection-to-an-unsecure-elasticsearch-node]

Identifies Elasticsearch nodes that do not have Transport Layer Security (TLS), and/or lack authentication, and are accepting inbound network connections over the default Elasticsearch port.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [docs-content://deploy-manage/deploy/self-managed/installing-elasticsearch.md](docs-content://deploy-manage/deploy/self-managed/installing-elasticsearch.md)
* [/beats/docs/reference/ingestion-tools/beats-packetbeat/packetbeat-http-options.md#_send_all_headers](beats://docs/reference/packetbeat/packetbeat-http-options.md#_send_all_headers)

**Tags**:

* Elastic
* Network
* Threat Detection
* Initial Access
* Host

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1253]

## Config

This rule requires the addition of port `9200` and `send_all_headers` to the `HTTP` protocol configuration in `packetbeat.yml`. See the References section for additional configuration documentation.

## Rule query [_rule_query_1319]

```js
event.category:network_traffic AND network.protocol:http AND status:OK AND destination.port:9200 AND network.direction:inbound AND NOT http.response.headers.content-type:"image/x-icon" AND NOT _exists_:http.request.headers.authorization
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



