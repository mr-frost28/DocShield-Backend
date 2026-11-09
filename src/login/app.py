import boto3
import json
import jwt
import requests
from boto3.dynamodb.conditions import Key
import os
from functools import lru_cache

# Initialize DynamoDB
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("docshield-users")

# Environment variables for Cognito
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

@lru_cache(maxsize=1)
def get_cognito_public_keys():
    """
    Fetch and cache Cognito public keys for JWT verification
    """
    url = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
    response = requests.get(url)
    return response.json()

def verify_jwt_token(token):
    """
    Verify JWT token from Cognito
    """
    try:
        # Decode token header to get the key ID
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        
        # Get public keys
        keys = get_cognito_public_keys()
        
        # Find the correct key
        key = None
        for k in keys['keys']:
            if k['kid'] == kid:
                key = k
                break
        
        if not key:
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
        
    except Exception as e:
        print(f"JWT verification failed: {str(e)}")
        return None

def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }

        if method == "POST":
            # Parse request body
            body = json.loads(event.get("body", "{}"))
            
            # For Cognito authentication, we expect either:
            # 1. JWT token in Authorization header (for token validation)
            # 2. Email in body (for user lookup after successful Cognito auth)
            
            # Get Authorization header
            headers = event.get("headers", {})
            auth_header = headers.get("Authorization") or headers.get("authorization")
            
            if auth_header and auth_header.startswith("Bearer "):
                # JWT token validation flow
                token = auth_header.split(" ")[1]
                payload = verify_jwt_token(token)
                
                if not payload:
                    return {
                        "statusCode": 401,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "Invalid or expired token"})
                    }
                
                # Get user email from token
                email = payload.get("email")
                if not email:
                    return {
                        "statusCode": 401,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "Email not found in token"})
                    }
                
                # Look up user in DynamoDB
                response = table.scan(
                    FilterExpression="email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                
                if not response.get("Items"):
                    return {
                        "statusCode": 404,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "User profile not found"})
                    }
                
                user = response["Items"][0]
                
                # Return user info
                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": "Authentication successful",
                        "user": {
                            "userid": user["userid"],
                            "email": user["email"],
                            "fname": user["fname"],
                            "lname": user["lname"],
                            "userType": user.get("userType", "Student"),
                            "institution": user.get("institution", ""),
                            "profileComplete": user.get("profileComplete", False)
                        },
                        "tokenPayload": {
                            "sub": payload.get("sub"),
                            "email": payload.get("email"),
                            "email_verified": payload.get("email_verified"),
                            "exp": payload.get("exp")
                        }
                    })
                }
            
            else:
                # Legacy email-based lookup (for backward compatibility)
                email = body.get("email")
                if not email:
                    return {
                        "statusCode": 400,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "Missing email or authorization token"})
                    }
                
                # Look up user in DynamoDB
                response = table.scan(
                    FilterExpression="email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                
                if not response.get("Items"):
                    return {
                        "statusCode": 404,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "User not found"})
                    }
                
                user = response["Items"][0]
                
                # Return basic user info (without full authentication)
                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": "User found",
                        "user": {
                            "userid": user["userid"],
                            "email": user["email"],
                            "fname": user["fname"],
                            "lname": user["lname"],
                            "userType": user.get("userType", "Student"),
                            "institution": user.get("institution", "")
                        }
                    })
                }

        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }
