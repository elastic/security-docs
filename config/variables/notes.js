const urls = require('./urls.js')
const terms = require('./terms.js')

const notes = {
  "ess-icon": `image:https://doc-icons.s3.us-east-2.amazonaws.com/logo_cloud.svg[link=\"${urls['ess-trial']}\", title=\"Supported on ${terms['ess']}\"]`,
  "ess-leadin": `You can run Elasticsearch on your own hardware or use our hosted Elasticsearch Service that is available on AWS, GCP, and Azure. ${urls['ess-trial']}[Try the Elasticsearch Service for free].`,
  "cloud-only": `This feature is designed for indirect use by ${urls['ess-trial']}[${terms['ess']}], ${urls['ece-ref']}[${terms['ece']}], and ${urls['eck-ref']}[${terms['eck']}]. Direct use is not supported.`,
  "ess-setting-change": `${terms['ess-icon']} indicates a change to a supported ${terms['cloud']}/ec-add-user-settings.html[user setting] for ${terms['ess']}.`,
  "ess-leadin-short": `Our hosted Elasticsearch Service is available on AWS, GCP, and Azure, and you can ${urls['ess-trial']}[try it for free].`,
  "multi-arg": "†footnoteref:[multi-arg,This parameter accepts multiple arguments.]",
  "multi-arg-ref": "†footnoteref:[multi-arg]",
}

module.exports = notes