const axios = require('axios')
const Promise = require('promise')
const fetch = require('cross-fetch')
const parser = require('./xmlParser.js')
const utf8 = require('utf8')
const FileInfo = require('./fileInfo.js')
const { v4: uuidv4 } = require('uuid')
const HttpError = require('./httpError.js')
const SignUrl = require('./owncloud-sign-url')

class helpers {
  constructor () {
    this.axios = axios.create({})
    this.OCS_BASEPATH = 'ocs/v1.php/'
    this.OCS_BASEPATH_V2 = 'ocs/v2.php/'
    this.OCS_SERVICE_SHARE = 'apps/files_sharing/api/v1'
    this.OCS_SERVICE_CLOUD = 'cloud'

    // constants from lib/public/constants.php
    this.OCS_PERMISSION_READ = 1
    this.OCS_PERMISSION_UPDATE = 2
    this.OCS_PERMISSION_CREATE = 4
    this.OCS_PERMISSION_DELETE = 8
    this.OCS_PERMISSION_SHARE = 16
    this.OCS_PERMISSION_ALL = 31

    // constants from lib/public/share.php
    this.OCS_SHARE_TYPE_USER = 0
    this.OCS_SHARE_TYPE_GROUP = 1
    this.OCS_SHARE_TYPE_LINK = 3
    this.OCS_SHARE_TYPE_REMOTE = 6

    this.instance = null
    this._authHeader = null
    this._headers = {}
    this._versionNumber = null
    this._currentUser = null
    this._signingKey = null
    this._authInterceptor = null
    this.fetch = fetch
  }

  /**
   * sets the OC instance
   * @param   {string}    instance    instance to be used for communication
   */
  setInstance (instance) {
    this.instance = instance
    this._webdavUrl = this.instance + 'remote.php/webdav'
    this._davPath = this.instance + 'remote.php/dav'
  }

  getInstance () {
    return this.instance
  }

  noAuth () {
    this.axios.interceptors.request.use(config => {
      config.extraReqParams = config.extraReqParams || {}
      config.extraReqParams.dontUseDefaultAuth = true
      return config
    })
  }

  /**
   * sets the username
   * @param   {string | null}    authHeader    authorization header; either basic or bearer or what ever
   */
  setAuthorization (authHeader) {
    this._authHeader = authHeader

    if (authHeader === null) {
      this.axios.interceptors.request.eject(this._authInterceptor)
    } else {
      this._authInterceptor = this.axios.interceptors.request.use(config => {
        if (config.extraReqParams && config.extraReqParams.dontUseDefaultAuth) {
          delete config.extraReqParams.dontUseDefaultAuth
          return config
        }
        if (authHeader && authHeader.startsWith('Bearer ')) {
          config.headers.Authorization = authHeader
          return config
        }
        return config
      })
    }
  }

  getAuthorization () {
    return this._authHeader
  }

  setHeaders (headers) {
    this._headers = headers
  }

  logout () {
    this.setAuthorization(null)
    this._currentUser = null
    this._signingKey = null
  }

  /**
   * Gets all capabilities of the logged in user
   * @returns {object}    all capabilities
   */
  getCapabilities () {
    return this._makeOCSrequest('GET', this.OCS_SERVICE_CLOUD, 'capabilities?format=json')
      .then(data => {
        const body = data.data.ocs.data
        this._versionNumber = body.version.major + '.' + body.version.minor + '.' + body.version.micro
        return Promise.resolve(body)
      })
  }

  /**
   * Gets the logged in user
   * @returns {object}    user info
   */
  getCurrentUser () {
    return this._currentUser
  }

  getCurrentUserAsync () {
    const user = this.getCurrentUser()
    if (user !== null) {
      return Promise.resolve(user)
    }
    return this._updateCurrentUser()
  }

  /**
   * Sets the logged in user
   * @param {object}  userInfo user info
   */
  setCurrentUser (userInfo) {
    this._currentUser = userInfo
  }

  /**
   * Updates the user logging in.
   * @returns {Promise.<_currentUser>}    object: _currentUser
   * @returns {Promise.<error>}           string: error message, if any.
   */
  _updateCurrentUser () {
    const self = this
    return self._makeOCSrequest('GET', self.OCS_SERVICE_CLOUD, 'user')
      .then(data => {
        self._currentUser = data.data.ocs.data

        return Promise.resolve(self._currentUser)
      })
  }

  /**
   *
   * @param {string} url
   * @param {number} ttl
   * @param {string} httpMethod
   *
   * @returns {Promise}
   */
  async signUrl (url, ttl = 1200, httpMethod = 'get') {
    const key = await this.getSignKey()
    const user = await this.getCurrentUser()
    const signUrl = new SignUrl({
      credential: user.id,
      secretKey: key,
      ttl: ttl,
      algorithm: 'sha512'
    })
    return signUrl.generateSignedUrl(url, httpMethod)
  }

  getSignKey () {
    if (this._signingKey !== null) {
      return Promise.resolve(this._signingKey)
    }
    const self = this
    return self._makeOCSrequest('GET', self.OCS_SERVICE_CLOUD, 'user/signing-key')
      .then(data => {
        self._signingKey = data.data.ocs.data['signing-key']

        return Promise.resolve(self._signingKey)
      })
  }

  setSigningKey (signingKey) {
    this._signingKey = signingKey
  }

  buildHeaders (withAuthHeader = true) {
    const headers = Object.assign({}, this._headers)
    headers['OCS-APIREQUEST'] = 'true'
    if (withAuthHeader) {
      headers.Authorization = this._authHeader
    }
    if (this.atLeastVersion('10.1.0')) {
      headers['X-Request-ID'] = uuidv4()
    }
    return headers
  }

  atLeastVersion (minVersion) {
    if (this._versionNumber === null) {
      return false
    }
    const semver = require('semver')
    return semver.gte(this._versionNumber, minVersion)
  }

  /**
   * Makes an OCS API request.
   * @param   {string} method     method of request (GET, POST etc.)
   * @param   {string} service    service (cloud, privatedata etc.)
   * @param   {string} action     action (apps?filter=enabled, capabilities etc.)
   * @param   {string} [data]     formData for POST and PUT requests
   * @returns {Promise.<data>}    object: {response: response, body: request body}
   * @returns {Promise.<error>}   string: error message, if any.
   */
  _makeOCSrequest (method, service, action, data) {
    const self = this

    if (!self.instance) {
      return Promise.reject('Please specify a server URL first')
    }

    if (!self._authHeader) {
      return Promise.reject('Please specify an authorization first.')
    }

    // Set the headers
    const headers = this.buildHeaders()
    let slash = ''

    if (service) {
      slash = '/'
    }
    const path = this.OCS_BASEPATH + service + slash + action

    // Configure the request
    const options = {
      url: this.instance + path,
      method: method,
      headers: headers
    }
    const serialize = function (element, key, list = []) {
      if (typeof (element) === 'object') {
        for (const idx in element) { serialize(element[idx], key ? key + '[' + idx + ']' : idx, list) }
      } else {
        list.push(encodeURIComponent(key) + '=' + encodeURIComponent(element))
      }
      return list.join('&')
    }

    options.headers['content-type'] = 'application/x-www-form-urlencoded'
    if (method !== 'GET' && method !== 'HEAD') {
      options.body = serialize(data).replace(/%20/g, '+')
    } else {
      options.body = null
    }

    return new Promise((resolve, reject) => {
      fetch(this.instance + path, {
        method: method,
        body: options.body,
        headers: headers
      })
        .then(res => {
          if (res.status >= 400) {
            reject(res.statusText)
          }
          return res
        })
        .then(async res => {
          let tree = null
          const body = await res.text()
          try {
            tree = parser.xml2js(body)
          } catch (e) {
            try {
              tree = JSON.parse(body)
            } catch (e) {
              reject(e)
            }
          }
          if ('message' in tree) {
            reject(tree.message)
          }
          const error = self._checkOCSstatus(tree)
          if (error) {
            reject(error)
          }
          res.statusCode = res.status
          resolve({
            response: res,
            body: body,
            data: tree
          })
        })
    })
  }

  /**
   * performs a simple GET request
   * @param   {string}    url     url to perform GET on
   * @returns {Promise.<data>}    object: {response: response, body: request body}
   * @returns {Promise.<error>}   string: error message, if any.
   */
  _get (url) {
    let err = null

    if (!this.instance) {
      err = 'Please specify a server URL first'
    }

    if (!this._authHeader) {
      err = 'Please specify an authorization first.'
    }

    const headers = {
      Authorization: this._authHeader,
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    return new Promise((resolve, reject) => {
      if (err) {
        reject(err)
        return
      }
      fetch(url, {
        method: 'GET',
        headers: headers
      })
        .then(async res => {
          res.statusCode = res.status
          resolve({
            response: res,
            body: await res.text()
          })
        })
    })
  }

  buildHttpErrorFromDavResponse (status, body) {
    const error = this._parseDAVerror(body)
    return new HttpError(status, error)
  }

  /**
   * Parses a DAV response error.
   */
  _parseDAVerror (body) {
    try {
      const tree = parser.xml2js(body)

      if (tree['d:error'] && tree['d:error']['s:message']) {
        const message = tree['d:error']['s:message']
        if (typeof message === 'string') {
          return message
        }
        return ''
      }
    } catch (error) {
      return 'Unknown error'
    }
    return 'Unknown error'
  }

  /**
   * Makes sure path starts with a '/'
   * @param   {string}    path    to the remote file share
   * @returns {string}            normalized path
   */
  _normalizePath (path) {
    if (!path) {
      path = ''
    }

    if (path.length === 0) {
      return '/'
    }

    if (path[0] !== '/') {
      path = '/' + path
    }

    return path
  }

  _encodeUri (path) {
    path = this._normalizePath(path)
    path = encodeURIComponent(path)
    return path.split('%2F').join('/')
  }

  /**
   * Checks the status code of an OCS request
   * @param   {object} json                         parsed response
   * @param   {array}  [acceptedCodes = [100] ]     array containing accepted codes
   * @returns {string}                              error message or NULL
   */
  _checkOCSstatus (json, acceptedCodes) {
    if (!acceptedCodes) {
      acceptedCodes = [100]
    }

    let meta
    if (json.ocs) {
      meta = json.ocs.meta
    }
    let ret

    if (meta && acceptedCodes.indexOf(parseInt(meta.statuscode)) === -1) {
      ret = meta.message

      if (Object.keys(meta.message).length === 0) {
        // no error message returned, return the whole message
        ret = json
      }
    }

    return ret
  }

  /**
   * Returns the status code of the xml response
   * @param   {object}    json    parsed response
   * @return  {number|null}       status-code
   */
  _checkOCSstatusCode (json) {
    if (json.ocs) {
      const meta = json.ocs.meta
      return parseInt(meta.statuscode)
    }
    return null
  }

  /**
   * Encodes the string according to UTF-8 standards
   * @param   {string}    path    path to be encoded
   * @returns {string}            encoded path
   */
  _encodeString (path) {
    return utf8.encode(path)
  }

  _buildFullWebDAVPath (path) {
    return this._encodeUri(path)
  }

  _buildFullWebDAVPathV2 (path) {
    return this._encodeUri(path)
  }

  _buildFullWebDAVURL (path) {
    return this._webdavUrl + this._encodeUri(path)
  }

  _buildFullWebDAVURLV2 (path) {
    return this._davPath + this._encodeUri(path)
  }

  /**
   * converts all of object's "true" or "false" entries to booleans
   * @param   {object}    object  object to be typecasted
   * @return  {object}            typecasted object
   */
  _convertObjectToBool (object) {
    if (typeof (object) !== 'object') {
      return object
    }

    for (const key in object) {
      if (object[key] === 'true') {
        object[key] = true
      }
      if (object[key] === 'false') {
        object[key] = false
      }
    }

    return object
  }

  /**
   * Handles Provisioning API boolean response
   */
  _OCSuserResponseHandler (data, resolve, reject) {
    const statuscode = parseInt(this._checkOCSstatusCode(data.data))
    if (statuscode === 999) {
      reject('Provisioning API has been disabled at your instance')
    }

    resolve(true)
  }

  /**
   *
   * @return {FileInfo[]}
   * @private
   */
  _parseBody (responses, leftTrimComponents = 0) {
    if (!Array.isArray(responses)) {
      responses = [responses]
    }
    const self = this
    const fileInfos = []
    for (let i = 0; i < responses.length; i++) {
      const fileInfo = self._parseFileInfo(responses[i], leftTrimComponents)
      if (fileInfo !== null) {
        fileInfos.push(fileInfo)
      }
    }
    return fileInfos
  }

  _extractPath (path, leftTrimComponents) {
    let pathSections = path.split('/')
    pathSections = pathSections.filter(function (section) {
      return section !== ''
    })

    const remoteIndex = pathSections.findIndex(section => decodeURIComponent(section) === 'remote.php')
    if (remoteIndex === -1) {
      return null
    }
    if (['webdav', 'dav'].indexOf(decodeURIComponent(pathSections[remoteIndex + 1])) === -1) {
      return null
    }

    // build the sub-path from the remaining sections
    leftTrimComponents = leftTrimComponents || 0
    let subPath = ''
    let i = remoteIndex + leftTrimComponents + 2
    while (i < pathSections.length) {
      subPath += '/' + decodeURIComponent(pathSections[i])
      i++
    }
    return subPath
  }

  /**
   * @return {FileInfo|null}
   * @private
   */
  _parseFileInfo (response, leftTrimComponents = 0) {
    const path = this._extractPath(response.href, leftTrimComponents)
    // invalid subpath
    if (path === null) {
      return null
    }
    const name = path

    if (response.propStat.length === 0 || response.propStat[0].status !== 'HTTP/1.1 200 OK') {
      return null
    }

    const props = response.propStat[0].properties
    let fileType = 'file'
    const resType = props['{DAV:}resourcetype']
    if (resType) {
      const node = resType[0]
      if (node === '{DAV:}collection') {
        fileType = 'dir'
      }
    }

    return new FileInfo(name, fileType, props)
  }

  _parseTusHeaders (response) {
    const result = {}

    const resHeaders = response.res.headers
    // hack to avoid logging the uncatchable "refused to get unsafe header"
    const allHeaders = Object.keys(response.res.headers).map(header => header.toLowerCase())
    if (allHeaders.indexOf('tus-version') < 0) {
      // backend did not expose TUS headers, unsupported
      return null
    }
    const version = resHeaders['tus-version']
    if (!version) {
      // TUS not supported
      return null
    }
    result.version = version.split(',')
    if (resHeaders['tus-extension']) {
      result.extension = resHeaders['tus-extension'].split(',')
    }
    if (resHeaders['tus-resumable']) {
      result.resumable = resHeaders['tus-resumable']
    }
    if (resHeaders['tus-max-size']) {
      result.maxSize = parseInt(resHeaders['tus-max-size'], 10)
    }
    return result
  }

  escapeXml (unsafe) {
    if (typeof unsafe !== 'string') {
      return unsafe
    }
    return unsafe.replace(/[<>&'"]/g, function (c) {
      switch (c) {
        case '<':
          return '&lt;'
        case '>':
          return '&gt;'
        case '&':
          return '&amp;'
        case '\'':
          return '&apos;'
        case '"':
          return '&quot;'
      }
    })
  }

  ocs (options = {}) {
    const defaults = {
      method: 'GET',
      service: this.OCS_SERVICE_CLOUD,
      action: 'user',
      data: null,
      headers: {},
      signal: null
    }
    options = Object.assign({}, defaults, options)
    const action = options.action.includes('?') ? options.action + '&format=json' : options.action + '?format=json'
    const url = this.instance + this.OCS_BASEPATH_V2 + options.service + '/' + action
    var headers = this.buildHeaders()
    headers['OCS-APIREQUEST'] = 'true'
    headers = Object.assign({}, headers, options.headers)
    const init = {
      method: options.method,
      mode: 'cors',
      headers: headers,
      signal: options.signal
    }
    if (options.data !== null) {
      init.body = JSON.stringify(options.data)
      init.headers['Content-Type'] = 'application/json'
    }
    return fetch(url, init)
  }
}

module.exports = helpers
