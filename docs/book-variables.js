import { variables } from '../../docs-staging.elastic.dev/config/variables.js'

const book = {
  "doctype": "book",
  "es-sec": `${variables["elastic-sec"]}`,
  "es-sec-app": `${variables["security-app"]}`,
  "es-sec-ui": `${variables["elastic-sec"]} UI`,
  "es-sec-endpoint": `${variables["elastic-defend"]}`,
  "siem-soln": `${variables["elastic-sec"]}`,
  "siem-app": `${variables["security-app"]}`,
  "siem-ui": `${variables["es-sec-ui"]}`,
  "ml-dir": `${variables["stack-docs-root"]}/docs/en/stack/ml`,
  "beats-dir": `${variables["beats-root"]}`,
  "kibana-dir": `${variables["kibana-root"]}/docs`,
  "issue": "https://github.com/elastic/kibana/issues/",
  "pull": "https://github.com/elastic/kibana/pull/",
  "security-docs-root": "../security-docs/docs",
  "docs-root": "../docs/shared/attributes.asciidoc",
  "stack-docs-root": "../stack-docs/docs/en"
}

export { book }