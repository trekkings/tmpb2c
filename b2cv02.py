import urllib3
import os
import json

import re
import jwt
import requests
import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import logging
logger = logging.getLogger(__name__)

openid_config=os.environ['ADB2C_OPENID_CONFIG']


class AzureVerifyTokenError(Exception):
    pass

class InvalidAuthorizationToken(AzureVerifyTokenError):
    def __init__(self, details=''):
        super().__init__(f'Invalid authorization token: {details}')
        
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


def get_public_key(token, jwks_uri):
    
    kid = get_kid(token)
    print('*********** kid is: ***************')
    print(kid)
    
    jwk = get_jwk(kid, jwks_uri)
    print('*********** jwk is: ***************')
    print(jwk)
    
    #return rsa_pem_from_jwk(get_jwk(get_kid(token)))
    
    rsa = rsa_pem_from_jwk(jwk)
    print('*********** rsa is: ***************')
    print(rsa)
    
    return rsa


def validate_jwt(jwt_to_validate, jwks_uri):
    print('*********** def validate_jwt jwt_to_validate is: ***************')
    print(jwt_to_validate)
    
    public_key = get_public_key(jwt_to_validate, jwks_uri)
    print('*********** def validate_jwt public key: ***************')
    print(public_key)

    # valid_audiences = "myself"
    # myissuer = "https://token.dev/jwks/"
    decoded = jwt.decode(jwt_to_validate, options={"verify_signature": False}) # works in PyJWT >= v2.0
    print('*********** DECODED: ***************')
    print (decoded)
    
    print('*********** issuer: ***************')
    print (decoded['iss'])
    iss = decoded['iss']
    
    print('*********** audience: ***************')
    print (decoded['aud'])
    aud = decoded['aud'] 

    try:
        #jwt.decode(jwt_to_validate, public_key, verify=True, algorithms=['RS256'], audience=valid_audiences, issuer=myissuer)
        jwt.decode(jwt_to_validate, public_key, verify=True, algorithms=['RS256'], audience=aud, issuer=iss)
        print('*********** decoded: JWT is validated: ***************')
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False                         

 
def get_jwks_uri(openid_config):
    resp = requests.get(openid_config)
    if not resp.ok:
        raise AzureVerifyTokenError(
            f'Received {resp.status_code} response code from {openid_config}'
        )
    try:
        uri = resp.json()
    except (ValueError, TypeError):
        raise AzureVerifyTokenError(
            f'Received malformed response from {openid_config}'
        )
    
    #jwks_uri = uri.get('jwks_uri')
    jwks_uri = uri['jwks_uri']
    print("************** def jwks_uri is: ******************")
    print(jwks_uri)
    
    return jwks_uri



def lambda_handler(event, context):
    
    #1 - Log the event
    print('*********** The event is: ***************')
    print(event)
    
    #2 - Log the context
    print('*********** The context: ***************')
    print(context)

    # openid_config = event['openid-config']
    # print('*********** openid_config: ***************')
    # print(openid_config)

    jwks_uri= get_jwks_uri(openid_config)
    print('*********** jwks_uri: ***************')
    print(jwks_uri)
    
    PREFIX = 'Bearer'
    auth_token = event['authorizationToken']
    
    bearer, _, token = auth_token.partition(' ')
    if bearer != PREFIX:
        raise ValueError('Invalid token')
    else:
        print('*********** The token: ***************')
        print(token) 

    principal_id = 'user'  # TODO
    policy = create_policy(event['methodArn'], principal_id)
    
    if token:
        
        jwt_validation = validate_jwt(token, jwks_uri)
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
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    HEAD    = "HEAD"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    ALL     = "*"

class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    
    restApiId = "<<restApiId>>"
    """ Replace the placeholder value with a default API Gateway API id to be used in the policy. 
    Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """    

    region = "<<region>>"
    """ Replace the placeholder value with a default region to be used in the policy. 
    Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """    

    stage = "<<stage>>"
    """ Replace the placeholder value with a default stage to be used in the policy. 
    Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
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

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy
      
