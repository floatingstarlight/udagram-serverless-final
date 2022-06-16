
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'


const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJeZz9CIxCJ5BKMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi03Y2ZhM3pmeC51cy5hdXRoMC5jb20wHhcNMjIwNTI2MTY0NTA2WhcN
MzYwMjAyMTY0NTA2WjAkMSIwIAYDVQQDExlkZXYtN2NmYTN6ZngudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA59in6nP4P3Z+koWK
G3Z64Q2kmHpXM9bgHJtgsdw3cztEO3is6GPOGZ6OC59VOkVHfVmsh5MmAuzbKy2I
0KjunB7fnpj1O5ldJh99KQF3WAB/DKKV7Heh0yT+3YvOxVk3/e2CpBcCAd1VeT2F
8H/jhdC1AVFdigp4qXtzifiiYcbdM//ppir3HkzuYBoFkCEytRVdUFH1n/yD2cuf
NEUgvDh/u1TFn8e1/hBD4sFBSJJaVj+z+u7/JMqkhsgkt/3ef+jQD4MxnAtbH95k
mIGZWPQSpVBsDMCRR2y4eo9Uz64f4ZfcNzYXlxIsumbL19uibwhS/2UbIK7U+2VK
FnE8owIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ+R6upzxDB
vhZj+mQwcusV2JyR8zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AM5HlLbqjHIObJt4NBSZL2RMaadHH2vvWXj29eqoG04c2t8UaUQM5ddglfc6pk21
2pK5YUo6QmDdh5VP05/mv0OjW4uVscNnNQ9mf+dR+GnFP9MW2pDGUc5kXFtECGAE
NbpFOD856AMO6esa1dsnz6J1eLhWbHO1pav2qBWIoQDdGP7safew6a6jfLCqasIS
O9n9qqf6lO8BUxRkjUbpFohz7KWl0z6H4nW5OAzYLRxO3Hiz8DW5hjpW/KFEbUpV
aaXHVOgmFf6guwvxsW2vmLbbWcWRlEmqsphJfd8l4PLzfXCID569fFn57QExR5Da
HdcsNxAsNWCRp71TIpoome8=
-----END CERTIFICATE-----`

export const handler = async (event :CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log("User authroized", jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User was not authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, {algorithms: ['RS256']}) as JwtToken
}

  


