const versions = require('./versions/current.js')

const elasticBaseUrl = "https://www.elastic.co"
const guideBaseUrl = `${elasticBaseUrl}/guide`
const discussBaseUrl = "https://discuss.elastic.co"
const ghBaseUrl = "https://github.com"

const ghRepos = {
  "es-repo": `${ghBaseUrl}/elastic/elasticsearch/`,
  "kib-repo": `${ghBaseUrl}/elastic/kibana/`,
  "ml-repo": `${ghBaseUrl}/elastic/ml-cpp/`,
  "apm-repo": `${ghBaseUrl}/elastic/apm-server/`,
}

const ghPages = {
  "es-issue": `${ghRepos['es-repo']}issues/`,
  "es-pull": `${ghRepos['es-repo']}pull/`,
  "es-commit": `${ghRepos['es-repo']}commit/`,
  "kib-issue": `${ghRepos['kib-repo']}/issues/`,
  "kib-pull": `${ghRepos['kib-repo']}/pull/`,
  "kibana-issue": `${ghRepos['kib-repo']}/issues`,
  "kibana-pull": `${ghRepos['kib-repo']}/pull`,
  "kib-commit": `${ghRepos['kib-repo']}commit/`,
  "ml-issue": `${ghRepos['ml-repo']}issues/`,
  "ml-pull": `${ghRepos['ml-repo']}pull/`,
  "ml-commit": `${ghRepos['ml-repo']}commit/`,
  "apm-issue": `${ghRepos['apm-repo']}issues/`,
  "apm-pull": `${ghRepos['apm-repo']}pull/`,
  "kibana-blob": `${ghRepos['kib-repo']}blob/${versions['branch']}/`,
}

const docUrls = {
  ////////////////////////////
  // APM
  ////////////////////////////
  "apm-guide-ref": `${guideBaseUrl}/en/apm/guide/${versions['branch']}`,
  // Agents
  "apm-agents-ref": `${guideBaseUrl}/en/apm/agent`,
  "apm-android-ref": `${guideBaseUrl}/en/apm/agent/android/current`,
  "apm-dotnet-ref": `${guideBaseUrl}/en/apm/agent/dotnet/current`,
  "apm-go-ref": `${guideBaseUrl}/en/apm/agent/go/current`,
  "apm-ios-ref": `${guideBaseUrl}/en/apm/agent/swift/current`,
  "apm-java-ref": `${guideBaseUrl}/en/apm/agent/java/current`,
  "apm-node-ref-index": `${guideBaseUrl}/en/apm/agent/nodejs`,
  "apm-node-ref": `${guideBaseUrl}/en/apm/agent/nodejs/current`,
  "apm-node-ref-1x": `${guideBaseUrl}/en/apm/agent/nodejs/1.x`,
  "apm-rum-ref": `${guideBaseUrl}/en/apm/agent/rum-js/current`,
  "apm-ruby-ref": `${guideBaseUrl}/en/apm/agent/ruby/current`,
  "apm-php-ref": `${guideBaseUrl}/en/apm/agent/php/current`,
  "apm-py-ref": `${guideBaseUrl}/en/apm/agent/python/current`,
  "apm-py-ref-3x": `${guideBaseUrl}/en/apm/agent/python/3.x`,
  // Lamba
  "apm-lambda-ref": `${guideBaseUrl}/en/apm/lambda/current`,
  // Attacher
  "apm-attacher-ref": `${guideBaseUrl}/en/apm/attacher/current`,
  // Old versions
  "apm-guide-7x": `${guideBaseUrl}/en/apm/guide/7.17`,
  "apm-get-started-ref": `${guideBaseUrl}/en/apm/get-started/${versions['branch']}`,
  "apm-server-ref": `${guideBaseUrl}/en/apm/server/${versions['branch']}`,
  "apm-server-ref-v": `${guideBaseUrl}/en/apm/server/${versions['branch']}`,
  "apm-server-ref-m": `${guideBaseUrl}/en/apm/server/master`,
  "apm-server-ref-62": `${guideBaseUrl}/en/apm/server/6.2`,
  "apm-server-ref-64": `${guideBaseUrl}/en/apm/server/6.4`,
  "apm-server-ref-70": `${guideBaseUrl}/en/apm/server/7.0`,
  "apm-overview-ref-v": `${guideBaseUrl}/en/apm/get-started/${versions['branch']}`,
  "apm-overview-ref-70": `${guideBaseUrl}/en/apm/get-started/7.0`,
  "apm-overview-ref-m": `${guideBaseUrl}/en/apm/get-started/master`,

  ////////////////////////////
  // Beats
  ////////////////////////////
  "beats-devguide": `${guideBaseUrl}/en/beats/devguide/${versions['branch']}`,
  "beats-ref-root": `${guideBaseUrl}/en/beats`,
  "beats-ref": `${guideBaseUrl}/en/beats/libbeat/${versions['branch']}`,
  "beats-ref-60": `${guideBaseUrl}/en/beats/libbeat/6.0`,
  "beats-ref-63": `${guideBaseUrl}/en/beats/libbeat/6.3`,
  "auditbeat-ref": `${guideBaseUrl}/en/beats/auditbeat/${versions['branch']}`,
  "filebeat-ref": `${guideBaseUrl}/en/beats/filebeat/${versions['branch']}`,
  "functionbeat-ref": `${guideBaseUrl}/en/beats/functionbeat/${versions['branch']}`,
  "heartbeat-ref": `${guideBaseUrl}/en/beats/heartbeat/${versions['branch']}`,
  "journalbeat-ref": `${guideBaseUrl}/en/beats/journalbeat/${versions['branch']}`,
  "metricbeat-ref": `${guideBaseUrl}/en/beats/metricbeat/${versions['branch']}`,
  "packetbeat-ref": `${guideBaseUrl}/en/beats/packetbeat/${versions['branch']}`,
  "winlogbeat-ref": `${guideBaseUrl}/en/beats/winlogbeat/${versions['branch']}`,
  "docker-logging-ref": `${guideBaseUrl}/en/beats/loggingplugin/${versions['branch']}`,

  ////////////////////////////
  // ECS
  ////////////////////////////
  "ecs-ref": `${guideBaseUrl}/en/ecs/${versions['ecs_version']}`,
  
  ////////////////////////////
  // ECS Logging
  ////////////////////////////
  "ecs-logging-ref": `${guideBaseUrl}/en/ecs-logging/overview/${versions['ecs-logging']}`,
  "ecs-logging-go-logrus-ref": `${guideBaseUrl}/en/ecs-logging/go-logrus/${versions['ecs-logging-go-logrus']}`,
  "ecs-logging-go-zap-ref": `${guideBaseUrl}/en/ecs-logging/go-zap/${versions['ecs-logging-go-zap']}`,
  "ecs-logging-java-ref": `${guideBaseUrl}/en/ecs-logging/java/${versions['ecs-logging-java']}`,
  "ecs-logging-dotnet-ref": `${guideBaseUrl}/en/ecs-logging/dotnet/${versions['ecs-logging-dotnet']}`,
  "ecs-logging-nodejs-ref": `${guideBaseUrl}/en/ecs-logging/nodejs/${versions['ecs-logging-nodejs']}`,
  "ecs-logging-php-ref": `${guideBaseUrl}/en/ecs-logging/php/${versions['ecs-logging-php']}`,
  "ecs-logging-python-ref": `${guideBaseUrl}/en/ecs-logging/python/${versions['ecs-logging-python']}`,
  "ecs-logging-ruby-ref": `${guideBaseUrl}/en/ecs-logging/ruby/${versions['ecs-logging-ruby']}`,

  ////////////////////////////
  // Elastic Cloud
  ////////////////////////////
  "cloud": `${guideBaseUrl}/en/cloud/current`,
  "ece-ref": `${guideBaseUrl}/en/cloud-enterprise/current`,
  "eck-ref": `${guideBaseUrl}/en/cloud-on-k8s/current`,

  ////////////////////////////
  // Elasticsearch
  ////////////////////////////
  "es-ref-dir": `../elasticsearch/docs/reference`,
  "ref": `${guideBaseUrl}/en/elasticsearch/reference/${versions['branch']}`,
  "ref-bare": `${guideBaseUrl}/en/elasticsearch/reference`,
  "hadoop-ref": `${guideBaseUrl}/en/elasticsearch/hadoop/${versions['branch']}`,
  // Clients
  "curator-ref": `${guideBaseUrl}/en/elasticsearch/client/curator/${versions['branch']}`,
  "curator-ref-current": `${guideBaseUrl}/en/elasticsearch/client/curator/current`,
  "eland-docs": `${guideBaseUrl}/en/elasticsearch/client/eland/current`,
  "es-dotnet-client": `${guideBaseUrl}/en/elasticsearch/client/net-api/${versions['branch']}`,
  "es-php-client": `${guideBaseUrl}/en/elasticsearch/client/php-api/${versions['branch']}`,
  "es-python-client": `${guideBaseUrl}/en/elasticsearch/client/python-api/${versions['branch']}`,
  "javaclient": `${guideBaseUrl}/en/elasticsearch/client/java-api/${versions['branch']}`,
  "java-api-client": `${guideBaseUrl}/en/elasticsearch/client/java-api-client/${versions['branch']}`,
  "java-rest": `${guideBaseUrl}/en/elasticsearch/client/java-rest/${versions['branch']}`,
  "jsclient": `${guideBaseUrl}/en/elasticsearch/client/javascript-api/${versions['branch']}`,
  "jsclient-current": `${guideBaseUrl}/en/elasticsearch/client/javascript-api/current`,
  "es-ruby-client": `${guideBaseUrl}/en/elasticsearch/client/ruby-api/${versions['branch']}`,
  // Painless
  "painless": `${guideBaseUrl}/en/elasticsearch/painless/${versions['branch']}`,
  // Plugins
  "plugins": `${guideBaseUrl}/en/elasticsearch/plugins/${versions['branch']}`,
  "plugins-8x": `${guideBaseUrl}/en/elasticsearch/plugins/8.1`,
  // SQL
  "sql-odbc": `${guideBaseUrl}/en/elasticsearch/sql-odbc/${versions['branch']}`,
  // Previous versions
  "defguide": `${guideBaseUrl}/en/elasticsearch/guide/2.x`,
  "ref-8x": `${guideBaseUrl}/en/elasticsearch/reference/8.1`,
  "ref-80": `${guideBaseUrl}/en/elasticsearch/reference/8.0`,
  "ref-7x": `${guideBaseUrl}/en/elasticsearch/reference/7.17`,
  "ref-70": `${guideBaseUrl}/en/elasticsearch/reference/7.0`,
  "ref-60": `${guideBaseUrl}/en/elasticsearch/reference/6.0`,
  "ref-64": `${guideBaseUrl}/en/elasticsearch/reference/6.4`,
  "plugins-6x": `${guideBaseUrl}/en/elasticsearch/plugins/6.8`,
  "plugins-7x": `${guideBaseUrl}/en/elasticsearch/plugins/7.17`,

  ////////////////////////////
  // Elastic Stack
  ////////////////////////////
  "stack-ref": `${guideBaseUrl}/en/elastic-stack/${versions['branch']}`,
  "glossary": `${guideBaseUrl}/en/elastic-stack-glossary/current`,
  // Overview
  "stack-ov": `${guideBaseUrl}/en/elastic-stack-overview/${versions['branch']}`,
  // Get started
  "stack-gs-current": `${guideBaseUrl}/en/elastic-stack-get-started/current`,
  "stack-gs": `${guideBaseUrl}/en/elastic-stack-get-started/${versions['branch']}`,
  // Old versions
  "stack-ref-67": `${guideBaseUrl}/en/elastic-stack/6.7`,
  "stack-ref-68": `${guideBaseUrl}/en/elastic-stack/6.8`,
  "stack-ref-70": `${guideBaseUrl}/en/elastic-stack/7.0`,

  ////////////////////////////
  // Enterprise Search
  ////////////////////////////
  "enterprise-search-ref": `${guideBaseUrl}/en/enterprise-search/${versions['branch']}`,
  "app-search-ref": `${guideBaseUrl}/en/app-search/${versions['branch']}`,
  "workplace-search-ref": `${guideBaseUrl}/en/workplace-search/${versions['branch']}`,
  // Clients
  "enterprise-search-node-ref": `${guideBaseUrl}/en/enterprise-search-clients/enterprise-search-node/${versions['branch']}`,
  "enterprise-search-php-ref": `${guideBaseUrl}/en/enterprise-search-clients/php/${versions['branch']}`,
  "enterprise-search-python-ref": `${guideBaseUrl}/en/enterprise-search-clients/python/${versions['branch']}`,
  "enterprise-search-ruby-ref": `${guideBaseUrl}/en/enterprise-search-clients/ruby/${versions['branch']}`,
  
  ////////////////////////////
  // ESF
  ////////////////////////////
  "esf-ref": `${guideBaseUrl}/en/esf/${versions['esf_version']}`,

  ////////////////////////////
  // Fleet
  ////////////////////////////
  "fleet-guide": `${guideBaseUrl}/en/fleet/${versions['branch']}`,

  ////////////////////////////
  // Ingest
  ////////////////////////////
  "ingest-guide": `${guideBaseUrl}/en/ingest/${versions['branch']}`,

  ////////////////////////////
  // Integration dev guide
  ////////////////////////////
  "integrations-devguide": `${guideBaseUrl}/en/integrations-developer/current`,

  ////////////////////////////
  // Kibana
  ////////////////////////////
  "kibana-ref-all": `${guideBaseUrl}/en/kibana`,
  "kibana-ref": `${guideBaseUrl}/en/kibana/${versions['branch']}`,
  "apm-app-ref": `${guideBaseUrl}/en/kibana/${versions['branch']}`,

  ////////////////////////////
  // Kinesis
  ////////////////////////////
  "kinesis-firehose-ref": `${guideBaseUrl}/en/kinesis/${versions['kinesis_version']}`,

  ////////////////////////////
  // Logstash
  ////////////////////////////
  "logstash-ref": `${guideBaseUrl}/en/logstash/${versions['branch']}`,
  
  ////////////////////////////
  // Machine learning
  ////////////////////////////
  "ml-docs": `${guideBaseUrl}/en/machine-learning/${versions['branch']}`,

  ////////////////////////////
  // Observability
  ////////////////////////////
  "observability-guide": `${guideBaseUrl}/en/observability/${versions['branch']}`,
  "observability-guide-all": `${guideBaseUrl}/en/observability`,

  ////////////////////////////
  // Security
  ////////////////////////////
  "siem-guide": `${guideBaseUrl}/en/siem/guide/${versions['branch']}`,
  "security-guide": `${guideBaseUrl}/en/security/${versions['branch']}`,
  "security-guide-all": `${guideBaseUrl}/en/security`,
  "endpoint-guide": `${guideBaseUrl}/en/endpoint/${versions['branch']}`,

  ////////////////////////////
  // Welcome to Elastic
  ////////////////////////////
  "estc-welcome-current": `${guideBaseUrl}/en/welcome-to-elastic/current`,
  "estc-welcome": `${guideBaseUrl}/en/welcome-to-elastic/${versions['branch']}`,
  "estc-welcome-all": `${guideBaseUrl}/en/welcome-to-elastic`,

  ////////////////////////////
  // X-Pack
  ////////////////////////////
  "xpack-ref": `${guideBaseUrl}/en/x-pack/6.2`,

  ////////////////////////////
  // Docs subdomain
  ////////////////////////////
  "integrations-docs": "https://docs.elastic.co/en/integrations",

  ////////////////////////////
  // Legacy docs
  ////////////////////////////
  "logs-ref": `${guideBaseUrl}/en/logs/${versions['branch']}`,
  "logs-guide": `${guideBaseUrl}/en/logs/guide/${versions['branch']}`,
  "metrics-ref": `${guideBaseUrl}/en/metrics/${versions['branch']}`,
  "metrics-guide": `${guideBaseUrl}/en/metrics/guide/${versions['branch']}`,
  "uptime-guide": `${guideBaseUrl}/en/uptime/${versions['branch']}`,
  "infra-guide": `${guideBaseUrl}/en/infrastructure/guide/${versions['branch']}`,
}

const otherUrls = {
  "apm-forum": `${discussBaseUrl}/c/apm`,
  "blog-ref": `${elasticBaseUrl}/blog/`,
  "byte-units": `${docUrls['ref']}/api-conventions.html#byte-units`,
  "elastic-maps-service": "https://maps.elastic.co",
  "eql-ref": "https://eql.readthedocs.io/en/latest/query-guide",
  "ess-baymax": "?baymax=docs-body&elektra=docs",
  "ess-console": "https://cloud.elastic.co?baymax=docs-body&elektra=docs",
  "ess-deployments": "https://cloud.elastic.co/deployments?baymax=docs-body&elektra=docs",
  "ess-product": `${elasticBaseUrl}/cloud/elasticsearch-service?baymax=docs-body&elektra=docs`,
  "ess-trial": `${elasticBaseUrl}/cloud/elasticsearch-service/signup?baymax=docs-body&elektra=docs`,
  "extendtrial": `${elasticBaseUrl}/trialextension`,
  "forum": `${discussBaseUrl}/`,
  "graph-forum": `${discussBaseUrl}/c/x-pack/graph`,
  "monitoring-forum": `${discussBaseUrl}/c/x-pack/marvel`,
  "security-forum": `${discussBaseUrl}/c/x-pack/shield`,
  "subscriptions": `${elasticBaseUrl}/subscriptions`,
  "time-units": `${docUrls['ref']}/api-conventions.html#time-units`,
  "upgrade_guide": `${elasticBaseUrl}/products/upgrade_guide`,
  "watcher-forum": `${discussBaseUrl}/c/x-pack/watcher`,
  "wikipedia": "https://en.wikipedia.org/wiki",
  "xpack-forum": `${discussBaseUrl}/c/50-x-pack`,
}

const urls = {
  ...ghRepos,
  ...ghPages,
  ...docUrls,
  ...otherUrls
}

module.exports = urls