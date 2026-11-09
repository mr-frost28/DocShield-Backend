import boto3
import json
import hashlib
import os
from boto3.dynamodb.conditions import Key

# Initialize DynamoDB
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("docshield-users")

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type"
}

def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight request
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }

        if method == "POST":
            # Parse request body
            body = json.loads(event.get("body", "{}"))
            
            email = body.get("email")
            # current_password = body.get("currentPassword")  # Commented out as per frontend
            new_password = body.get("newPassword")
            confirm_password = body.get("confirmPassword")

            # Validate required fields
            if not all([email, new_password, confirm_password]):
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing required fields: email, newPassword, confirmPassword"})
                }

            # Validate password match
            if new_password != confirm_password:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Passwords do not match"})
                }

            # Validate password length (minimum 6 characters as per frontend validation)
            if len(new_password) < 6:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Password must be at least 6 characters"})
                }

            # Generate new salt and hash for new password
            new_salt = os.urandom(16).hex()
            new_password_hash = hashlib.sha256((new_password + new_salt).encode("utf-8")).hexdigest()

            try:
                # Find user by email using scan (consistent with login/signup functions)
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
                userid = user["userid"]
                
                # Update user password using the found userid
                table.update_item(
                    Key={"userid": userid},
                    UpdateExpression="SET passhash = :new_hash, salt = :new_salt",
                    ExpressionAttributeValues={
                        ":new_hash": new_password_hash,
                        ":new_salt": new_salt
                    }
                )
                
            except Exception as e:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": f"Database error: {str(e)}"})
                }

            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": "Password changed successfully"
                })
            }

        # Method not allowed
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