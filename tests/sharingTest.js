import { MatchersV3, XmlBuilder } from '@pact-foundation/pact/v3'

const { fromProviderState } = MatchersV3
const {
  toFormUrlEncoded,
  getShareIdToken
} = require('./helpers/sharingHelper')

const {
  givenUserExists,
  givenGroupExists,
  givenShareExists,
  givenFileFolderIsCreated,
  givenResourceIsShared
} = require('./helpers/providerStateHelper')

describe('Main: Currently testing file/folder sharing,', function () {
  const config = require('./config/config.json')

  const {
    applicationXmlResponseHeaders,
    applicationFormUrlEncoded,
    htmlResponseHeaders,
    getCapabilitiesInteraction,
    getCurrentUserInformationInteraction,
    createOwncloud,
    ocsMeta,
    shareResponseOcsData,
    createProvider,
    getAuthHeaders
  } = require('./pactHelper.js')

  // TESTING CONFIGS
  const testUserPassword = config.testUserPassword
  const testGroup = config.testGroup
  const testFolder = config.testFolder
  const nonExistentFile = config.nonExistentFile
  const expirationDate = config.expirationDate
  const testFiles = config.testFiles
  const testFilesId = config.testFilesId

  const sharer = config.testUser
  const sharerPassword = config.testUserPassword
  const sharee = config.testUser2
  const shareePassword = config.testUser2Password

  const validAuthHeaders = {
    authorization: getAuthHeaders(sharer, sharerPassword)
  }

  // CREATED SHARES
  const sharedFiles = {
    'test space and + and #.txt': 18,
    'test.txt': 14,
    '文件.txt': 19
  }
  const testFolderShareID = config.testFolderId

  // CONSTANTS FROM lib/public/constants.php
  const OCS_PERMISSION_READ = 1
  const OCS_PERMISSION_UPDATE = 2
  const OCS_PERMISSION_SHARE = 16

  const getIsSharedInteraction = async function (
    provider,
    requestName,
    shareType,
    resource,
    resourceType = 'file'
  ) {
    const { shareId, shareToken } = getShareIdToken(resource, resourceType)
    await givenUserExists(provider, sharer, sharerPassword)
    await givenFileFolderIsCreated(provider, sharer, sharerPassword, resource, resourceType)
    await givenResourceIsShared(provider, sharer, sharerPassword, resource, shareType)

    resource = '/' + resource
    const body = new XmlBuilder('1.0', '', 'ocs').build(ocs => {
      ocs.appendElement('meta', '', (meta) => {
        ocsMeta(meta, 'ok', '100')
      }).appendElement('data', '', data => {
        data.appendElement('element', '', element => {
          shareResponseOcsData(element, shareType, shareId, 1, resource)
            .appendElement('token', '', fromProviderState('${token}', shareToken)) /* eslint-disable-line no-template-curly-in-string */
        })
      })
    })

    return provider
      .uponReceiving(`as ${sharer}, a GET request to ${requestName}`)
      .withRequest({
        method: 'GET',
        path: MatchersV3.regex(
          '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
          '/ocs/v1.php/apps/files_sharing/api/v1/shares'
        ),
        query: { path: resource },
        headers: validAuthHeaders
      }).willRespondWith({
        status: 200,
        headers: {
          ...applicationXmlResponseHeaders
        },
        body
      })
  }

  const getSharesInteraction = async function (provider, resource, resourceType = 'file') {
    await givenUserExists(provider, sharer, sharerPassword)
    await givenFileFolderIsCreated(provider, sharer, sharerPassword, resource, resourceType)

    await givenUserExists(provider, sharee, shareePassword)
    await givenGroupExists(provider, testGroup)
    // shares file/folder with user, group and public link
    await givenShareExists(provider, sharer, sharerPassword, resource, 3)
    await givenShareExists(provider, sharer, sharerPassword, resource, 0, sharee)
    await givenShareExists(provider, sharer, sharerPassword, resource, 1, testGroup)

    resource = '/' + resource
    const body = new XmlBuilder('1.0', '', 'ocs').build(ocs => {
      ocs.appendElement('meta', '', (meta) => {
        ocsMeta(meta, 'ok', '100')
      }).appendElement('data', '', data => {
        data.appendElement('element', '', element => {
          shareResponseOcsData(element, 0, 101, 1, resource)
            .appendElement('token', '', fromProviderState('${token}', '5Bvt5fDajGxiV3P')) /* eslint-disable-line no-template-curly-in-string */
        })
        data.appendElement('element', '', element => {
          shareResponseOcsData(element, 1, 102, 1, resource)
            .appendElement('token', '', fromProviderState('${token}', '6Bvt5fDajGxiV3Q')) /* eslint-disable-line no-template-curly-in-string */
        })
        data.appendElement('element', '', element => {
          shareResponseOcsData(element, 3, 103, 1, resource)
            .appendElement('token', '', fromProviderState('${token}', '7Bvt5fDajGxiV3R')) /* eslint-disable-line no-template-curly-in-string */
        })
      })
    })

    return provider
      .uponReceiving(`as ${sharer}, a GET request to get all shares of ${resourceType} '${resource}'`)
      .withRequest({
        method: 'GET',
        path: MatchersV3.regex(
          '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
          '/ocs/v1.php/apps/files_sharing/api/v1/shares'
        ),
        query: { path: resource },
        headers: validAuthHeaders
      }).willRespondWith({
        status: 200,
        headers: {
          ...applicationXmlResponseHeaders
        },
        body
      })
  }

  const getShareInteraction = async (
    provider,
    requestName,
    shareType,
    resource,
    resourceType
  ) => {
    const { shareId, shareToken } = getShareIdToken(resource, resourceType)
    await givenUserExists(provider, sharer, sharerPassword)
    await givenFileFolderIsCreated(provider, sharer, sharerPassword, resource, resourceType)
    await givenResourceIsShared(provider, sharer, sharerPassword, resource, shareType)
    resource = '/' + resource

    const body = new XmlBuilder('1.0', '', 'ocs').build(ocs => {
      ocs.appendElement('meta', '', (meta) => {
        ocsMeta(meta, 'ok', '100')
      }).appendElement('data', '', data => {
        data.appendElement('element', '', element => {
          shareResponseOcsData(element, shareType, shareId, 1, resource)
            .appendElement('token', '', fromProviderState('${token}', shareToken)) /* eslint-disable-line no-template-curly-in-string */
        })
      })
    })
    return provider
      .uponReceiving(`as ${sharer}, a GET request to get single share of '${resource}' ${requestName}`)
      .withRequest({
        method: 'GET',
        path: fromProviderState(
          '/ocs/v1.php/apps/files_sharing/api/v1/shares/${id}', /* eslint-disable-line no-template-curly-in-string */
          `/ocs/v1.php/apps/files_sharing/api/v1/shares/${shareId}`
        ),
        headers: validAuthHeaders
      })
      .willRespondWith({
        status: 200,
        headers: applicationXmlResponseHeaders,
        body
      })
  }

  const updateShareInteraction = async (
    provider,
    requestName,
    shareType,
    resource,
    resourceType,
    formData,
    additionalBodyElement
  ) => {
    const { shareId, shareToken } = getShareIdToken(resource, resourceType)
    let permissions = 1
    await givenUserExists(provider, sharer, sharerPassword)
    await givenFileFolderIsCreated(provider, sharer, sharerPassword, resource, resourceType)
    await givenResourceIsShared(provider, sharer, sharerPassword, resource, shareType)

    if (formData.permissions) {
      permissions = formData.permissions
    } else if (formData.publicUpload) {
      permissions = 15
    }

    resource = '/' + resource
    const body = new XmlBuilder('1.0', '', 'ocs').build(ocs => {
      ocs.appendElement('meta', '', (meta) => {
        ocsMeta(meta, 'ok', '100')
      }).appendElement('data', '', data => {
        const node = shareResponseOcsData(data, shareType, shareId, permissions, resource)
          .appendElement('token', '', fromProviderState('${token}', shareToken)) /* eslint-disable-line no-template-curly-in-string */
        if (additionalBodyElement) {
          for (const prop in additionalBodyElement) {
            node.appendElement(prop, '', additionalBodyElement[prop])
          }
        }
      })
    })
    return provider
      .uponReceiving(`as ${sharer}, a PUT request to update share of '${resource}' ${requestName}`)
      .withRequest({
        method: 'PUT',
        path: fromProviderState(
          '/ocs/v1.php/apps/files_sharing/api/v1/shares/${id}', /* eslint-disable-line no-template-curly-in-string */
          `/ocs/v1.php/apps/files_sharing/api/v1/shares/${shareId}`
        ),
        body: toFormUrlEncoded(formData),
        headers: {
          ...validAuthHeaders,
          ...applicationFormUrlEncoded
        }
      })
      .willRespondWith({
        status: 200,
        headers: applicationXmlResponseHeaders,
        body
      })
  }

  describe('Currently testing folder sharing,', function () {
    describe('sharedFolderByLink,', function () {
      describe('checking the shared folder,', function () {
        it('checking method : isShared with shared folder', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getIsSharedInteraction(
            provider,
            `check whether '${testFolder}' is shared or not (public link share)`,
            3,
            testFolder,
            'folder'
          )

          await provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.isShared(testFolder).then(status => {
              expect(status).toEqual(true)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('checking method : getShare with existent share', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getShareInteraction(provider, '(public link share)', 3, testFolder, 'folder')
          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            await oc.shares.getShare(testFolder).then(share => {
              expect(typeof (share)).toBe('object')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
      describe('updating share information,', function () {
        it('enabling publicUpload', async function () {
          const formData = { publicUpload: true }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(public link share: enable publicUpload)',
            3,
            testFolder,
            'folder',
            formData
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(share => {
              expect(share.getPermissions()).toEqual(15)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('adding password', async function () {
          const formData = { password: '1234' }
          const additionalBodyElement = {
            share_with: '***redacted***',
            share_with_displayname: '***redacted***'
          }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(public link share: set share password)',
            3,
            testFolder,
            'folder',
            formData,
            additionalBodyElement
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(async share => {
              expect(typeof (share.getShareWith())).toEqual('string')
              expect(typeof (share.getShareWithDisplayName())).toEqual('string')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
    })

    describe('sharedFolderWithUser,', function () {
      describe('checking the shared folder,', function () {
        it('checking method : isShared with shared folder', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getIsSharedInteraction(
            provider,
            `check whether '${testFolder}' is shared or not (user share)`,
            0,
            testFolder,
            'folder'
          )

          await provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.isShared(testFolder).then(status => {
              expect(status).toEqual(true)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('checking method : getShare with existent share', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getShareInteraction(provider, '(user share)', 0, testFolder, 'folder')
          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            await oc.shares.getShare(testFolder).then(share => {
              expect(typeof (share)).toBe('object')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
      describe('updating shared information,', function () {
        it('updating permissions to read/write', async function () {
          const formData = { permissions: 15 }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(user share: set read/write permission)',
            0,
            testFolder,
            'folder',
            formData
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(share => {
              expect(share.getPermissions()).toEqual(15)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('adding password', async function () {
          const formData = { password: '1234' }
          const additionalBodyElement = {
            share_with: sharee,
            share_with_displayname: sharee
          }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(user share: set share password)',
            0,
            testFolder,
            'folder',
            formData,
            additionalBodyElement
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(async share => {
              expect(typeof (share.getShareWith())).toEqual('string')
              expect(typeof (share.getShareWithDisplayName())).toEqual('string')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
    })

    describe('sharedFolderWithGroup,', function () {
      describe('checking the shared folder,', function () {
        it('checking method : isShared with shared folder', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getIsSharedInteraction(
            provider,
            `check whether '${testFolder}' is shared or not (group share)`,
            1,
            testFolder,
            'folder'
          )

          await provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.isShared(testFolder).then(status => {
              expect(status).toEqual(true)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('checking method : getShare with existent share', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getShareInteraction(provider, '(group share)', 1, testFolder, 'folder')
          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            await oc.shares.getShare(testFolder).then(share => {
              expect(typeof (share)).toBe('object')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
      describe('updating shared information,', function () {
        it('updating permissions to read/write', async function () {
          const formData = { permissions: 15 }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(group share: set read/write permission)',
            0,
            testFolder,
            'folder',
            formData
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(share => {
              expect(share.getPermissions()).toEqual(15)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })

        it('adding password', async function () {
          const formData = { password: '1234' }
          const additionalBodyElement = {
            share_with: testGroup,
            share_with_displayname: testGroup
          }
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await updateShareInteraction(
            provider,
            '(group share: set share password)',
            1,
            testFolder,
            'folder',
            formData,
            additionalBodyElement
          )

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            return oc.shares.updateShare(testFolderShareID, formData).then(async share => {
              expect(typeof (share.getShareWith())).toEqual('string')
              expect(typeof (share.getShareWithDisplayName())).toEqual('string')
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        })
      })
    })

    it('checking method : getShares for shared folder', async function () {
      const provider = createProvider()
      await getCapabilitiesInteraction(provider, sharer, sharerPassword)
      await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
      await getSharesInteraction(provider, testFolder, 'folder')

      return provider.executeTest(async () => {
        const oc = createOwncloud(sharer, sharerPassword)
        await oc.login()
        return oc.shares.getShares(testFolder).then(shares => {
          expect(shares.constructor).toBe(Array)
          expect(shares.length).toEqual(3)
        }).catch(error => {
          expect(error).toBe(null)
        })
      })
    })
  })

  describe('Currently testing file sharing,', function () {
    describe('sharedFilesByLink,', function () {
      describe('checking the shared files,', function () {
        it('checking method : isShared with shared file', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          for (let i = 0; i < testFiles.length; i++) {
            await getIsSharedInteraction(
              provider,
              `check whether '${testFiles[i]}' is shared or not (public link share)`,
              3,
              testFiles[i]
            )
          }

          await provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()

            for (let i = 0; i < testFiles.length; i++) {
              await oc.shares.isShared(testFiles[i]).then(status => {
                expect(status).toEqual(true)
              }).catch(error => {
                expect(error).toBe(null)
              })
            }
          })
        })

        // TODO: adjust the test after the issue is resolved
        // refactor test to have loops like in other working tests
        // https://github.com/pact-foundation/pact-js/issues/604
        it('checking method : getShare with existent share', async function () {
          for (let i = 0; i < testFiles.length; i++) {
            const provider = createProvider()
            await getCapabilitiesInteraction(provider, sharer, sharerPassword)
            await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
            await getShareInteraction(provider, '(public link share)', 3, testFiles[i])
            await provider.executeTest(async () => {
              const oc = createOwncloud(sharer, sharerPassword)
              await oc.login()
              await oc.shares.getShare(testFilesId[i]).then(share => {
                expect(typeof (share)).toBe('object')
                expect(Object.values(testFilesId).indexOf(share.getId())).toBeGreaterThan(-1)
              }).catch(error => {
                expect(error).toBe(null)
              })
            })
          }
        })
      })
    })

    describe('sharedFilesWithUser,', function () {
      describe('updating shared file permissions', function () {
        // TODO: adjust the test after the issue is resolved
        // refactor test to have loops like in other working tests
        // https://github.com/pact-foundation/pact-js/issues/604
        it('update permissions', async function () {
          const maxPerms = OCS_PERMISSION_READ + OCS_PERMISSION_UPDATE + OCS_PERMISSION_SHARE
          const formData = { permissions: maxPerms }

          for (let i = 0; i < testFiles.length; i++) {
            const provider = createProvider()
            await getCapabilitiesInteraction(provider, sharer, sharerPassword)
            await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
            await updateShareInteraction(
              provider,
              '(user share: set max permission)',
              0,
              testFiles[i],
              '',
              formData
            )

            await provider.executeTest(async () => {
              const oc = createOwncloud(sharer, sharerPassword)
              await oc.login()
              await oc.shares.updateShare(testFilesId[i], formData).then(share => {
                expect(share.getPermissions()).toEqual(maxPerms)
              }).catch(error => {
                expect(error).toBe(null)
              })
            })
          }
        })
      })

      describe('checking method :', function () {
        it('isShared with shared file', async function () {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          for (const file of testFiles) {
            await getIsSharedInteraction(
              provider,
              `check whether '${file}' is shared or not (user share)`,
              0,
              file
            )
          }
          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            for (const file in sharedFiles) {
              await oc.shares.isShared(file).then(status => {
                expect(status).toEqual(true)
              }).catch(error => {
                expect(error).toBe(null)
              })
            }
          })
        })

        // TODO: adjust the test after the issue is resolved
        // refactor test to have loops like in other working tests
        // https://github.com/pact-foundation/pact-js/issues/604
        it('getShare with existent share', async function () {
          for (let i = 0; i < testFiles.length; i++) {
            const provider = createProvider()
            await getCapabilitiesInteraction(provider, sharer, sharerPassword)
            await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
            await getShareInteraction(provider, '(user share)', 0, testFiles[i])

            return provider.executeTest(async () => {
              const oc = createOwncloud(sharer, sharerPassword)
              await oc.login()
              await oc.shares.getShare(testFilesId[i]).then(share => {
                expect(typeof (share)).toBe('object')
                expect(share.getId()).toBeGreaterThan(-1)
              }).catch(error => {
                expect(error).toBe(null)
              })
            })
          }
        })
      })
    })

    describe('sharedFilesWithGroup,', function () {
      it('checking method : isShared with shared file', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        for (const file of config.testFiles) {
          await getIsSharedInteraction(
            provider,
            `check whether '${file}' is shared or not (group share)`,
            1,
            file
          )
        }
        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return Promise.all(Object.keys(sharedFiles).map(key => {
            return oc.shares.isShared(key).then(status => {
              expect(status).toEqual(true)
            }).catch(error => {
              expect(error).toBe(null)
            })
          }))
        })
      })

      // TODO: adjust the test after the issue is resolved
      // refactor test to have loops like in other working tests
      // https://github.com/pact-foundation/pact-js/issues/604
      it('checking method : getShare with existent share', async function () {
        for (let i = 0; i < testFiles.length; i++) {
          const provider = createProvider()
          await getCapabilitiesInteraction(provider, sharer, sharerPassword)
          await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
          await getShareInteraction(provider, '(group share)', 1, testFiles[i])

          return provider.executeTest(async () => {
            const oc = createOwncloud(sharer, sharerPassword)
            await oc.login()
            await oc.shares.getShare(testFilesId[i]).then(share => {
              expect(typeof (share)).toBe('object')
              expect(share.getId()).toBeGreaterThan(-1)
            }).catch(error => {
              expect(error).toBe(null)
            })
          })
        }
      })
    })

    it('checking method : getShares for shared file', async function () {
      const provider = createProvider()
      await getCapabilitiesInteraction(provider, sharer, sharerPassword)
      await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)

      for (const file of testFiles) {
        await getSharesInteraction(provider, file)
      }

      return provider.executeTest(async () => {
        const oc = createOwncloud(sharer, sharerPassword)
        await oc.login()
        for (const file of testFiles) {
          await oc.shares.getShares(file).then(shares => {
            expect(shares.constructor).toBe(Array)
            expect(shares.length).toEqual(3)
          }).catch(error => {
            expect(error).toBe(null)
          })
        }
      })
    })

    describe('checking method: ', function () {
      async function linkSharePOSTNonExistentFile (provider) {
        await givenUserExists(provider, sharer, sharerPassword)
        return provider.uponReceiving(`as '${sharer}', a POST request to create a public link share with non-existent file`)
          .withRequest({
            method: 'POST',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares'
            ),
            headers: {
              ...validAuthHeaders,
              ...applicationFormUrlEncoded
            },
            body: 'shareType=3' + '&path=%2F' + nonExistentFile + '&password=' + testUserPassword
          }).willRespondWith({
            status: 200,
            headers: {
              ...applicationXmlResponseHeaders
            },
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'failure', 404, 'Wrong path, file/folder doesn\'t exist')
              }).appendElement('data', '', '')
            })
          })
      }
      async function groupSharePOSTNonExistentFile (provider) {
        await givenUserExists(provider, sharer, sharerPassword)
        await givenGroupExists(provider, testGroup)
        return provider.uponReceiving(`as '${sharer}', a POST request to share non-existent file with existing group`)
          .withRequest({
            method: 'POST',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares'
            ),
            headers: {
              ...validAuthHeaders,
              ...applicationFormUrlEncoded
            },
            body: 'shareType=1&shareWith=' + testGroup + '&path=%2F' + nonExistentFile + '&permissions=19'
          }).willRespondWith({
            status: 200,
            headers: applicationXmlResponseHeaders,
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'failure', 404, 'Wrong path, file/folder doesn\'t exist')
              }).appendElement('data', '', '')
            })
          })
      }
      async function shareGETNonExistentFile (provider, name = '') {
        await givenUserExists(provider, sharer, sharerPassword)
        return provider.uponReceiving(`as '${sharer}', a GET request to get share information of non-existent file '${name}'`)
          .withRequest({
            method: 'GET',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares'
            ),
            query: { path: '/' + config.nonExistentFile },
            headers: validAuthHeaders
          }).willRespondWith({
            status: 200,
            headers: {
              ...applicationXmlResponseHeaders
            },
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'failure', 404, 'Wrong path, file/folder doesn\'t exist')
              }).appendElement('data', '', '')
            })
          })
      }
      async function shareGETExistingNonSharedFile (provider, name, fileName) {
        await givenUserExists(provider, sharer, sharerPassword)
        await givenFileFolderIsCreated(provider, sharer, sharerPassword, fileName)
        return provider
          .uponReceiving(`as '${sharer}', a GET request to get share information of existent but non-shared file '${name}'`)
          .withRequest({
            method: 'GET',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares'
            ),
            query: { path: '/' + fileName },
            headers: validAuthHeaders
          })
          .willRespondWith({
            status: 200,
            headers: {
              ...applicationXmlResponseHeaders
            },
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'ok', 100)
              }).appendElement('data', '', '')
            })
          })
      }
      function shareGetNonExistentShare (provider) {
        return provider.uponReceiving(`as '${sharer}', a GET request to get non-existent share`)
          .withRequest({
            method: 'GET',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares\\/-1$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares/-1'
            ),
            headers: validAuthHeaders
          })
          .willRespondWith({
            status: 200,
            headers: applicationXmlResponseHeaders,
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'failure', 404, 'Wrong share ID, share doesn\'t exist')
              }).appendElement('data', '', '')
            })
          })
      }
      function putFileWithExmptyContent (provider) {
        return provider.uponReceiving(`as '${sharer}', a PUT request to put file contents as empty content in files specified`)
          .withRequest({
            method: 'PUT',
            path: MatchersV3.regex(
              '.*\\/remote\\.php\\/webdav\\/newFileCreated123$',
              '/remote.php/webdav/newFileCreated123'
            ),
            headers: validAuthHeaders
          })
          .willRespondWith({
            status: 201,
            headers: {
              ...htmlResponseHeaders
            }
          })
      }

      async function sharePOSTRequestWithExpirationDateSet (provider, fileEncoded, file) {
        await givenUserExists(provider, sharer, sharerPassword)
        await givenUserExists(provider, sharee, shareePassword)
        await givenFileFolderIsCreated(provider, sharer, sharerPassword, file)
        return provider
          .uponReceiving(`as '${sharer}', a POST request to share a file '${file}' to user with expiration date set`)
          .withRequest({
            method: 'POST',
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares'
            ),
            headers: {
              ...validAuthHeaders,
              ...applicationFormUrlEncoded
            },
            body: 'shareType=0&shareWith=' + sharee + '&path=' + fileEncoded + '&expireDate=' + config.expirationDate
          })
          .willRespondWith({
            status: 200,
            headers: applicationXmlResponseHeaders,
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'ok', 100)
              }).appendElement('data', '', data => {
                shareResponseOcsData(data, 0, config.testFilesId[testFiles.indexOf(file)], 19, '/' + file)
                  .appendElement('expiration', '', config.expirationDate + ' 00:00:00')
              })
            })
          })
      }

      function updateDeleteShareNonExistent (provider, method) {
        return provider
          .uponReceiving(`as '${sharer}', a ${method} request to update/delete a non-existent share`)
          .withRequest({
            method,
            path: MatchersV3.regex(
              '.*\\/ocs\\/v1\\.php\\/apps\\/files_sharing\\/api\\/v1\\/shares\\/-1$',
              '/ocs/v1.php/apps/files_sharing/api/v1/shares/-1'
            ),
            headers: validAuthHeaders
          })
          .willRespondWith({
            status: 200,
            headers: {
              ...applicationXmlResponseHeaders
            },
            body: new XmlBuilder('1.0', '', 'ocs').build(ocs => {
              ocs.appendElement('meta', '', (meta) => {
                ocsMeta(meta, 'failure', 404, 'Wrong share ID, share doesn\'t exist')
              }).appendElement('data', '', '')
            })
          })
      }

      it('shareFileWithLink with non-existent file', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await linkSharePOSTNonExistentFile(provider)
        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.shareFileWithLink(nonExistentFile, { password: testUserPassword }).then(status => {
            expect(status).toBe(null)
          }).catch(error => {
            expect(error.toLowerCase()).toBe('wrong path, file/folder doesn\'t exist')
          })
        })
      })

      it('shareFileWithGroup with non existent file', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await groupSharePOSTNonExistentFile(provider)

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.shareFileWithGroup(nonExistentFile, testGroup, { permissions: 19 }).then(share => {
            expect(share).toBe(null)
          }).catch(error => {
            expect(error.toLowerCase()).toBe('wrong path, file/folder doesn\'t exist')
          })
        })
      })

      it('isShared with non existent file', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await shareGETNonExistentFile(provider, 'for testing isShared')

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.isShared(nonExistentFile).then(status => {
            expect(status).toBe(null)
          }).catch(error => {
            expect(error.toLowerCase()).toBe('wrong path, file/folder doesn\'t exist')
          })
        })
      })

      it('isShared with existent but non shared file', async function () {
        const suffix = '123'
        const fileName = 'newFileCreated' + suffix

        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await putFileWithExmptyContent(provider)
        await shareGETExistingNonSharedFile(provider, '', fileName)

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.files.putFileContents(fileName).then(status => {
            expect(typeof status).toBe('object')
            return oc.shares.isShared(fileName)
          }).then(isShared => {
            expect(isShared).toEqual(false)
          }).catch(error => {
            expect(error).toBe(null)
          })
        })
      })

      it('getShare with non existent share', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await shareGetNonExistentShare(provider)

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.getShare(-1).then(share => {
            expect(share).toBe(null)
          }).catch(error => {
            if (error.slice(-1) === '.') {
              error = error.slice(0, -1)
            }
            expect(error.toLowerCase()).toEqual('wrong share id, share doesn\'t exist')
          })
        })
      })

      it('getShares for non existent file', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await shareGETNonExistentFile(provider, 'for testing getShares')

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.getShares(nonExistentFile).then(shares => {
            expect(shares).toBe(null)
          }).catch(error => {
            expect(error.toLowerCase()).toBe('wrong path, file/folder doesn\'t exist')
          })
        })
      })

      it('getShares for existent but non shared file', async function () {
        const suffix = '123'
        const fileName = 'newFileCreated' + suffix

        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await putFileWithExmptyContent(provider)
        await shareGETExistingNonSharedFile(provider, 'testing getShares', fileName)

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.files.putFileContents(fileName).then(status => {
            expect(typeof status).toBe('object')
            return oc.shares.getShares(fileName)
          }).then(shares => {
            expect(shares.constructor).toEqual(Array)
            expect(shares.length).toEqual(0)
          }).catch(error => {
            expect(error).toBe(null)
          })
        })
      })

      it('updateShare for non existent share', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await updateDeleteShareNonExistent(provider, 'PUT')

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.updateShare(-1).then(status => {
            expect(status).toBe(null)
          }).catch(error => {
            if (error.slice(-1) === '.') {
              error = error.slice(0, -1)
            }
            expect(error.toLowerCase()).toBe('wrong share id, share doesn\'t exist')
          })
        })
      })

      it('deleteShare with non existent share', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)
        await updateDeleteShareNonExistent(provider, 'DELETE')

        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()
          return oc.shares.deleteShare(-1).then(status => {
            expect(status).toBe(true)
          }).catch(error => {
            if (error.slice(-1) === '.') {
              error = error.slice(0, -1)
            }
            expect(error.toLowerCase()).toBe('wrong share id, share doesn\'t exist')
          })
        })
      })

      it('should share a file with another user when expiration date is set', async function () {
        const provider = createProvider()
        await getCapabilitiesInteraction(provider, sharer, sharerPassword)
        await getCurrentUserInformationInteraction(provider, sharer, sharerPassword)

        for (let i = 0; i < config.testFilesPath.length; i++) {
          await sharePOSTRequestWithExpirationDateSet(provider, config.testFilesPath[i], testFiles[i])
        }
        return provider.executeTest(async () => {
          const oc = createOwncloud(sharer, sharerPassword)
          await oc.login()

          await Promise.all(testFiles.map(file => {
            return oc.shares.shareFileWithUser(
              file,
              sharee,
              { expirationDate: expirationDate }
            ).then(share => {
              expect(share).not.toBe(null)
              expect(typeof share).toBe('object')
              expect(typeof share.getId()).toBe('number')
              expect(typeof share.getExpiration()).toBe('number')
            }).catch(error => {
              fail(error)
            })
          }))
        })
      })
    })
  })
})
