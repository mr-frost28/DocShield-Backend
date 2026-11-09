import json
import boto3
from boto3.dynamodb.conditions import Attr
import datetime
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
    "Access-Control-Allow-Methods": "OPTIONS,POST,PUT,GET",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token,X-Requested-With,Accept,Origin,Access-Control-Request-Method,Access-Control-Request-Headers",
    "Access-Control-Allow-Credentials": "false",
    "Access-Control-Max-Age": "86400"
}

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = "docshield-users"
table = dynamodb.Table(TABLE_NAME)

# @require_auth  # Uncomment this when auth_utils is properly deployed
def lambda_handler(event, context):
    try:
        # Log the incoming event for debugging
        print(f"Received event: {json.dumps(event)}")
        
        method = event.get("httpMethod", "")
        print(f"HTTP Method: {method}")

        # Handle CORS preflight
        if method == "OPTIONS":
            print("Handling OPTIONS preflight request")
            print(f"Headers in request: {event.get('headers', {})}")
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }

        if method in ["POST", "PUT"]:
            # Parse request body
            body = json.loads(event.get("body", "{}"))
            print(f"Request body: {body}")
            print(f"Available fields in body: {list(body.keys())}")
            
            # Try to get email from JWT token first
            user_email = get_user_email_from_token(event)
            
            # If no token, fall back to request body or query params
            if not user_email:
                query_params = event.get("queryStringParameters") or {}
                user_email = body.get("email") or query_params.get("userEmail")
                
            print(f"User email: {user_email}")
            
            if not user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing user email or authorization token"})
                }
            
            # Basic email validation
            if "@" not in user_email or "." not in user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Invalid email format"})
                }

            # First, find the user by email to get the userid (partition key)
            print(f"Scanning for user with email: {user_email}")
            try:
                scan_response = table.scan(
                    FilterExpression=Attr('email').eq(user_email),
                    ProjectionExpression="userid"
                )
                
                items = scan_response.get("Items", [])
                print(f"Found {len(items)} users")
                
                if not items:
                    return {
                        "statusCode": 404,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "User not found"})
                    }
                
                user_id = items[0]["userid"]
                print(f"User ID: {user_id}")
                
            except Exception as db_error:
                print(f"Database scan error: {str(db_error)}")
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Database error while finding user", "details": str(db_error)})
                }

            # Prepare update expression and attribute values
            update_expression_parts = []
            expression_attribute_values = {}
            expression_attribute_names = {}

            # Personal Details
            if "fname" in body and body["fname"]:
                update_expression_parts.append("#fname = :fname")
                expression_attribute_names["#fname"] = "fname"
                expression_attribute_values[":fname"] = body["fname"]
                
            if "firstName" in body and body["firstName"]:
                update_expression_parts.append("#fname = :fname")
                expression_attribute_names["#fname"] = "fname"
                expression_attribute_values[":fname"] = body["firstName"]

            if "lname" in body and body["lname"]:
                update_expression_parts.append("#lname = :lname")
                expression_attribute_names["#lname"] = "lname"
                expression_attribute_values[":lname"] = body["lname"]
                
            if "lastName" in body and body["lastName"]:
                update_expression_parts.append("#lname = :lname")
                expression_attribute_names["#lname"] = "lname"
                expression_attribute_values[":lname"] = body["lastName"]

            if "phone" in body and body["phone"]:
                update_expression_parts.append("phone = :phone")
                expression_attribute_values[":phone"] = body["phone"]

            # Cognito-related fields
            if "userType" in body and body["userType"]:
                update_expression_parts.append("userType = :userType")
                expression_attribute_values[":userType"] = body["userType"]

            if "institution" in body and body["institution"]:
                update_expression_parts.append("institution = :institution")
                expression_attribute_values[":institution"] = body["institution"]

            # Professional Details
            if "profileType" in body and body["profileType"]:
                update_expression_parts.append("profileType = :profileType")
                expression_attribute_values[":profileType"] = body["profileType"]

            # Handle both 'designation' and 'Designation' field names
            designation_value = body.get("designation") or body.get("Designation")
            if designation_value:
                update_expression_parts.append("designation = :designation")
                expression_attribute_values[":designation"] = designation_value

            # Handle both 'organization' and 'Organization' field names
            organization_value = body.get("organization") or body.get("Organization")
            if organization_value:
                update_expression_parts.append("organization = :organization")
                expression_attribute_values[":organization"] = organization_value

            # Academic Details
            if "educationLevel" in body and body["educationLevel"]:
                update_expression_parts.append("educationLevel = :educationLevel")
                expression_attribute_values[":educationLevel"] = body["educationLevel"]

            if "degreeName" in body and body["degreeName"]:
                update_expression_parts.append("degreeName = :degreeName")
                expression_attribute_values[":degreeName"] = body["degreeName"]

            # Mark profile as complete if it's an update with substantial data
            if len(update_expression_parts) > 1:  # More than just timestamp
                update_expression_parts.append("profileComplete = :profileComplete")
                expression_attribute_values[":profileComplete"] = True

            # Add last updated timestamp
            update_expression_parts.append("lastUpdated = :lastUpdated")
            expression_attribute_values[":lastUpdated"] = datetime.datetime.utcnow().isoformat()

            if not update_expression_parts:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "No valid fields to update"})
                }

            # Build the update expression
            update_expression = "SET " + ", ".join(update_expression_parts)
            print(f"Update expression: {update_expression}")
            print(f"Expression attribute values: {expression_attribute_values}")

            # Update the user profile
            update_params = {
                "Key": {"userid": user_id},
                "UpdateExpression": update_expression,
                "ExpressionAttributeValues": expression_attribute_values,
                "ReturnValues": "ALL_NEW"
            }

            # Add expression attribute names if needed
            if expression_attribute_names:
                update_params["ExpressionAttributeNames"] = expression_attribute_names

            print(f"Update params: {update_params}")
            
            try:
                response = table.update_item(**update_params)
                print(f"DynamoDB response: {response}")

                # Return updated user data (excluding sensitive fields)
                updated_user = response["Attributes"]
                
                # Remove sensitive fields from response
                if "passhash" in updated_user:
                    del updated_user["passhash"]
                if "salt" in updated_user:
                    del updated_user["salt"]

                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": "Profile updated successfully",
                        "user": updated_user
                    })
                }
                
            except Exception as update_error:
                print(f"Database update error: {str(update_error)}")
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Database error while updating profile", "details": str(update_error)})
                }

        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"})
        }

    except Exception as e:
        print(f"Error: {str(e)}")  # For CloudWatch logs
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Internal server error", "details": str(e)})
        }