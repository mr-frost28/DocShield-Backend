import boto3
import json
import uuid
import datetime
import hashlib
import os

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
            fname = body.get("fname")
            lname = body.get("lname")
            password = body.get("password")

            # Validate required fields
            if not all([email, fname, lname, password]):
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing required fields"})
                }

            # Check if email already exists (scan method)
            response = table.scan(
                FilterExpression="email = :email",
                ExpressionAttributeValues={":email": email}
            )

            if response.get("Items"):
                return {
                    "statusCode": 409,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Email already registered"})
                }

            # Generate unique userId (UUID)
            user_id = str(uuid.uuid4())

            # Generate a random salt
            salt = os.urandom(16).hex()

            # Hash the password with SHA-256 + salt
            password_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

            # Account creation timestamp (UTC ISO format)
            acreation = datetime.datetime.utcnow().isoformat()

            # Save user in DynamoDB
            table.put_item(
                Item={
                    "userid": user_id,
                    "email": email,
                    "fname": fname,
                    "lname": lname,
                    "passhash": password_hash,
                    "salt": salt,
                    "acreation": acreation
                }
            )

            return {
                "statusCode": 201,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": "User registered successfully",
                    "userid": user_id
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
