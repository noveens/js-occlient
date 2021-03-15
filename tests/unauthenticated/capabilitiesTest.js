describe('Unauthenticated: Currently testing getConfig, getVersion and getCapabilities', function () {
  const OwnCloud = require('../../src')
  const config = require('../config/config.json')

  // LIBRARY INSTANCE
  let oc

  beforeEach(function () {
    oc = new OwnCloud({
      baseUrl: config.backendHost
    })
  })

  it('checking method : getConfig', function (done) {
    oc.getConfig().then(config => {
      expect(config).toBe(null)
      done()
    }).catch(error => {
      expect(error).toMatch('Please specify an authorization first.')
      done()
    })
  })

  it('checking method : getCapabilities', function (done) {
    oc.getCapabilities().then(capabilities => {
      expect(capabilities).toBe(null)
      done()
    }).catch(error => {
      expect(error).toBe('Please specify an authorization first.')
      done()
    })
  })
})
