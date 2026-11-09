import boto3
import json
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

# Initialize DynamoDB
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("docshield-users")

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST,PUT",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

# @require_auth  # Uncomment when auth_utils is deployed
def lambda_handler(event, context):
    """
    Complete user profile after simplified signup
    This endpoint allows users to provide additional details after the basic email/password signup
    """
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight request
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }

        if method in ["POST", "PUT"]:
            # Parse request body
            body = json.loads(event.get("body", "{}"))

            # Try to get email from JWT token first
            user_email = get_user_email_from_token(event)
            
            # If no token, fall back to request body
            if not user_email:
                user_email = body.get("email")
                
            if not user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing user email or authorization token"})
                }

            # Find the user by email
            response = table.scan(
                FilterExpression="email = :email",
                ExpressionAttributeValues={":email": user_email}
            )

            items = response.get("Items", [])
            if not items:
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "User not found"})
                }

            user_id = items[0]["userid"]
            existing_user = items[0]

            # Prepare update expression and values
            update_expression_parts = []
            expression_attribute_values = {}
            expression_attribute_names = {}

            # Handle name fields (both firstName/lastName and fname/lname)
            first_name = body.get("firstName") or body.get("fname")
            last_name = body.get("lastName") or body.get("lname")
            
            if first_name and first_name.strip():
                update_expression_parts.append("#fname = :fname")
                expression_attribute_names["#fname"] = "fname"
                expression_attribute_values[":fname"] = first_name.strip()

            if last_name and last_name.strip():
                update_expression_parts.append("#lname = :lname")
                expression_attribute_names["#lname"] = "lname"
                expression_attribute_values[":lname"] = last_name.strip()

            # User type (Student, Verifier, Admin)
            if "userType" in body and body["userType"]:
                valid_user_types = ["Student", "Verifier", "Admin"]
                if body["userType"] in valid_user_types:
                    update_expression_parts.append("userType = :userType")
                    expression_attribute_values[":userType"] = body["userType"]

            # Institution/Organization
            if "institution" in body:
                update_expression_parts.append("institution = :institution")
                expression_attribute_values[":institution"] = body["institution"]

            # Phone number
            if "phone" in body:
                update_expression_parts.append("phone = :phone")
                expression_attribute_values[":phone"] = body["phone"]

            # Professional details
            if "designation" in body:
                update_expression_parts.append("designation = :designation")
                expression_attribute_values[":designation"] = body["designation"]

            if "organization" in body:
                update_expression_parts.append("organization = :organization")
                expression_attribute_values[":organization"] = body["organization"]

            # Academic details
            if "educationLevel" in body:
                update_expression_parts.append("educationLevel = :educationLevel")
                expression_attribute_values[":educationLevel"] = body["educationLevel"]

            if "degreeName" in body:
                update_expression_parts.append("degreeName = :degreeName")
                expression_attribute_values[":degreeName"] = body["degreeName"]

            # Profile completion
            if "profileComplete" in body:
                update_expression_parts.append("profileComplete = :profileComplete")
                expression_attribute_values[":profileComplete"] = bool(body["profileComplete"])
            elif len(update_expression_parts) >= 2:  # If updating substantial data
                update_expression_parts.append("profileComplete = :profileComplete")
                expression_attribute_values[":profileComplete"] = True

            # Add completion timestamp
            update_expression_parts.append("profileCompletionTimestamp = :completionTime")
            expression_attribute_values[":completionTime"] = datetime.datetime.utcnow().isoformat()

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

            # Prepare update parameters
            update_params = {
                "Key": {"userid": user_id},
                "UpdateExpression": update_expression,
                "ExpressionAttributeValues": expression_attribute_values,
                "ReturnValues": "ALL_NEW"
            }

            if expression_attribute_names:
                update_params["ExpressionAttributeNames"] = expression_attribute_names

            # Execute update
            response = table.update_item(**update_params)
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
                    "message": "Profile completed successfully",
                    "user": updated_user,
                    "profileComplete": updated_user.get("profileComplete", False),
                    "updatedFields": list(expression_attribute_values.keys())
                })
            }

        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"})
        }

    except Exception as e:
        print(f"Error in complete_profile: {str(e)}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }