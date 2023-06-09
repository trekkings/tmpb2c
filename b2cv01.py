import logging

import re
import requests
import jwt

#from .crypto import rsa_pem_from_jwk

import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization



logger = logging.getLogger(__name__)


# obtain jwks as you wish: configuration file, HTTP GET request to the endpoint returning them;
jwks = {
    "keys": [
        {
            "kid": "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk",
            "nbf": 1493763266,
            "use": "sig",
            "kty": "RSA",
            "e": "AQAB",
            "n": "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw"
        }
    ]
}

# configuration, these can be seen in valid JWTs from Azure B2C:
valid_audiences = ['d7f48c21-2a19-4bdb-ace8-48928bff0eb5'] # id of the application prepared previously
issuer = 'https://ugrose.b2clogin.com/9c2984ff-d596-4e5c-8e74-672be7b592e3/v2.0/' # iss



class AzureVerifyTokenError(Exception):
    pass


class InvalidAuthorizationToken(AzureVerifyTokenError):
    def __init__(self, details=''):
        super().__init__(f'Invalid authorization token: {details}')


def verify_jwt(
    *,
    token,
    valid_audiences,
    jwks_uri,
    issuer,
    verify=True,
    options=None,
    **kwargs,
):
    public_key = get_public_key(token=token, jwks_uri=jwks_uri)
    try:
        decoded = jwt.decode(
            token,
            public_key,
            verify=verify,
            algorithms=['RS256'],
            audience=valid_audiences,
            issuer=issuer,
            options=options or {},
            **kwargs,
        )
    except jwt.exceptions.PyJWTError as exc:
        raise InvalidAuthorizationToken(exc.__class__.__name__)
    else:
        return decoded


def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('headers missing')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('kid missing from headers')


def get_jwk(kid, jwks_uri):
    resp = requests.get(jwks_uri)
    if not resp.ok:
        raise AzureVerifyTokenError(
            f'Received {resp.status_code} response code from {jwks_uri}'
        )
    try:
        jwks = resp.json()
    except (ValueError, TypeError):
        raise AzureVerifyTokenError(
            f'Received malformed response from {jwks_uri}'
        )
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


# def get_public_key(*, token, jwks_uri):
#     kid = get_kid(token)
#     jwk = get_jwk(kid=kid, jwks_uri=jwks_uri)
#     return rsa_pem_from_jwk(jwk)

def get_public_key(token):
    
    kid = get_kid(token)
    print('*********** kid is: ***************')
    print(kid)
    
    #jwk = get_jwk(kid=kid, jwks_uri="https://token.dev/jwks/keys.json")
    jwk = get_jwk(kid=kid, jwks_uri="https://login.windows.net/common/discovery/keys")
    print('*********** jwk is: ***************')
    print(jwk)
    
    #return rsa_pem_from_jwk(get_jwk(get_kid(token)))
    
    rsa = rsa_pem_from_jwk(jwk)
    print('*********** rsa is: ***************')
    print(rsa)
    
    return rsa_pem_from_jwk(jwk)



# crypto
def ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key


def decode_value(val):
    decoded = base64.urlsafe_b64decode(ensure_bytes(val) + b'==')
    return int.from_bytes(decoded, 'big')


def rsa_pem_from_jwk(jwk):
    return RSAPublicNumbers(
        n=decode_value(jwk['n']),
        e=decode_value(jwk['e'])
    ).public_key(default_backend()).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
#
def validate_jwt(jwt_to_validate):
    print('*********** jwt_to_validate is: ***************')
    print(jwt_to_validate)
    
    public_key = get_public_key(jwt_to_validate)
    print('*********** public key: ***************')
    print(public_key)

    # valid_audiences = "myself"
    # myissuer = "https://token.dev/jwks/"
    
    valid_audiences = "https://management.core.windows.net/"
    myissuer = "https://sts.windows.net/88efcb31-2e14-4e15-b283-10dd0aaf78b8/"

    # decoded = jwt.decode(jwt_to_validate,
    #                      public_key,
    #                      verify=True,
    #                      algorithms=['RS256'],
    #                      audience=valid_audiences,
    #                      issuer=myissuer)

    try:
        jwt.decode(jwt_to_validate, public_key, verify=True, algorithms=['RS256'], audience=valid_audiences, issuer=myissuer)
        print('*********** decoded: JWT is validated: ***************')
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False                         

    # do what you wish with decoded token:
    # if we get here, the JWT is validated
    
    # print('*********** decoded: JWT is validated: ***************')
    # print(decoded)

 
    

def lambda_handler(event, context):
    
    #1 - Log the event
    print('*********** The event is: ***************')
    print(event)
    print("ID token         :: " + event['authorizationToken'])
    print("Method ARN       :: " + event['methodArn'])    
    
    # #2 - See if the person's token is valid
    # if event['authorizationToken'] == 'abc123':
    #     auth = 'Allow'
    # else:
    #     auth = 'Deny'

    #2 - Log the context
    print('*********** The context: ***************')
    print(context)
    print("Lambda function ARN          :: ", context.invoked_function_arn)
    print("CloudWatch log stream name   :: ", context.log_stream_name)
    print("CloudWatch log group name    :: ",  context.log_group_name)
    print("Lambda Request ID            :: ", context.aws_request_id)

    '''
    Validate the incoming token and produce the principal user identifier
    associated with the token. This can be accomplished in a number of ways:

    1. Call out to the OAuth provider
    2. Decode a JWT token inline
    3. Lookup in a self-managed DB
    '''

    # #3 - Construct and return the response
    # authResponse = { "principalId": "abc123", "policyDocument": { "Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke", "Resource": ["arn:aws:execute-api:ap-east-1:623703055341:a4x47spyti/mytest/GET/mytest"], "Effect": auth}] }}
    # return authResponse
    
    #token = event['authorizationToken']  # retrieve the Auth token
    
    PREFIX = 'Bearer'
    auth_token = event['authorizationToken']

    bearer, _, token = auth_token.partition(' ')
    if bearer != PREFIX:
        raise ValueError('Invalid token')
    else:
        print('*********** The token: ***************')
        print(token) 

    principal_id = 'abc123'  # fake

    policy = create_policy(event['methodArn'], principal_id)
    

    # if event['authorizationToken']:
    #     #user_info = auth_token_decode(token)
    #     print('*********** The token: ***************')
    #     print(token)
    if token:
        
        jwt_validation = validate_jwt(token)
        print('*********** jwt_validation ***************')
        print(jwt_validation)
        
        if jwt_validation:
            policy.allowAllMethods()
        else:
            policy.denyAllMethods()
    else:
       policy.denyAllMethods()

    return policy.build()

def create_policy(method_arn, principal_id):
    tmp = method_arn.split(':')
    region = tmp[3]
    account_id = tmp[4]
    api_id, stage = tmp[5].split('/')[:2]

    policy = AuthPolicy(principal_id, account_id)
    policy.restApiId = api_id
    policy.region = region
    policy.stage = stage

    return policy

class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId,
                                                                     self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
    
