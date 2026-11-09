import json
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
import sys
import os

# Add the parent directory to the path to import auth_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from auth_utils import require_auth, get_user_email_from_token
except ImportError:
    # Fallback if auth_utils is not available
    def require_auth(func):
        return func
    def get_user_email_from_token(event):
        return None

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,GET",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = "docshield-users"
table = dynamodb.Table(TABLE_NAME)

def decimal_default(obj):
    """Helper function to handle Decimal objects in JSON serialization"""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError

# @require_auth  # Uncomment this when auth_utils is properly deployed
def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"}, default=decimal_default)
            }

        if method == "GET":
            # Try to get email from JWT token first
            user_email = get_user_email_from_token(event)
            
            # If no token, fall back to query parameter
            if not user_email:
                params = event.get("queryStringParameters", {}) or {}
                user_email = params.get("userEmail")
                
            if not user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing userEmail parameter or authorization token"}, default=decimal_default)
                }
                
            # Scan DynamoDB for user with the given email
            scan_response = table.scan(
                FilterExpression=Attr('email').eq(user_email),
                ProjectionExpression="fname, lname, email, phone, profileType, designation, organization, educationLevel, degreeName, userRole, userType, institution, profileComplete"
            )
            
            items = scan_response.get("Items", [])
            if not items:
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "User not found"}, default=decimal_default)
                }
                
            user = items[0]
            user_details = {
                "fname": user.get("fname", ""),
                "lname": user.get("lname", ""),
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "profileType": user.get("profileType", ""),
                "designation": user.get("designation", ""),
                "organization": user.get("organization", ""),
                "educationLevel": user.get("educationLevel", ""),
                "degreeName": user.get("degreeName", ""),
                "userRole": user.get("userRole", ""),
                "userType": user.get("userType", "Student"),
                "institution": user.get("institution", ""),
                "profileComplete": user.get("profileComplete", False)
            }
            
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps(user_details, default=decimal_default)
            }

        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"}, default=decimal_default)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)}, default=decimal_default)
        }
