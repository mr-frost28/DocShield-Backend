"""
Authentication utilities for AWS Cognito JWT token validation
"""
import json
import jwt
import requests
import os
from functools import lru_cache

# Environment variables for Cognito
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
AWS_REGION = os.environ.get('AWS_REGION', 'us-west-1')

@lru_cache(maxsize=1)
def get_cognito_public_keys():
    """
    Fetch and cache Cognito public keys for JWT verification
    """
    try:
        url = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Failed to fetch Cognito public keys: {str(e)}")
        return None

def verify_jwt_token(token):
    """
    Verify JWT token from Cognito
    Returns payload if valid, None if invalid
    """
    try:
        # Decode token header to get the key ID
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        
        # Get public keys
        keys = get_cognito_public_keys()
        if not keys:
            return None
        
        # Find the correct key
        key = None
        for k in keys['keys']:
            if k['kid'] == kid:
                key = k
                break
        
        if not key:
            print(f"Key with kid {kid} not found")
            return None
            
        # Convert JWK to PEM format
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        
        # Verify and decode token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience=None,  # We'll verify this manually if needed
            issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}"
        )
        
        return payload
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        print(f"JWT verification failed: {str(e)}")
        return None

def extract_token_from_event(event):
    """
    Extract JWT token from API Gateway event
    Returns token string or None
    """
    headers = event.get("headers", {})
    
    # Try different header cases
    auth_header = (
        headers.get("Authorization") or 
        headers.get("authorization") or 
        headers.get("AUTHORIZATION")
    )
    
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    
    return None

def require_auth(func):
    """
    Decorator to require JWT authentication for Lambda functions
    """
    def wrapper(event, context):
        try:
            token = extract_token_from_event(event)
            
            if not token:
                return {
                    "statusCode": 401,
                    "headers": {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"
                    },
                    "body": json.dumps({"error": "Missing authorization token"})
                }
            
            payload = verify_jwt_token(token)
            
            if not payload:
                return {
                    "statusCode": 401,
                    "headers": {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"
                    },
                    "body": json.dumps({"error": "Invalid or expired token"})
                }
            
            # Add user info to event for use in the handler
            event['cognitoUser'] = {
                'sub': payload.get('sub'),
                'email': payload.get('email'),
                'email_verified': payload.get('email_verified'),
                'exp': payload.get('exp'),
                'token_use': payload.get('token_use')
            }
            
            return func(event, context)
            
        except Exception as e:
            return {
                "statusCode": 500,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({"error": f"Authentication error: {str(e)}"})
            }
    
    return wrapper

def get_user_email_from_token(event):
    """
    Get user email from the validated token in the event
    """
    cognito_user = event.get('cognitoUser', {})
    return cognito_user.get('email')

def get_user_id_from_token(event):
    """
    Get user ID (sub) from the validated token in the event
    """
    cognito_user = event.get('cognitoUser', {})
    return cognito_user.get('sub')