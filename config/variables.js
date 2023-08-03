const versions = require('./variables/versions/current.js')
const terms = require('./variables/terms.js')
const urls = require('./variables/urls.js')
const icons = require('./variables/icons.js')
const notes = require('./variables/notes.js')

const sandbox = {
  eui: 'Elastic _User_ **Interface**',
  catName: 'Erwin',
  isengard: "They're taking the **hobbits** to Isengard!",
}

const variables = {
  nbsp: '&nbsp;',
  ...sandbox,
  ...versions,
  ...terms,
  ...urls,
  ...icons,
  ...notes,
}

module.exports = { variables }
