import boto3
import json
import uuid
import datetime
import sys
import os

# Add the parent directory to the path to import auth_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from auth_utils import require_auth, get_user_email_from_token, get_user_id_from_token
except ImportError:
    # Fallback if auth_utils is not available
    def require_auth(func):
        return func
    def get_user_email_from_token(event):
        return None
    def get_user_id_from_token(event):
        return None

# Initialize AWS services
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("docshield-users")
cognito_client = boto3.client('cognito-idp')

# Environment variables for Cognito
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

@require_auth
def lambda_handler(event, context):
    """
    Sync user data between Cognito and DynamoDB
    This function:
    1. Gets user info from the JWT token
    2. Fetches additional user attributes from Cognito
    3. Creates or updates user profile in DynamoDB
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

        if method == "POST":
            # Get user info from JWT token
            user_email = get_user_email_from_token(event)
            cognito_user_id = get_user_id_from_token(event)
            
            if not user_email or not cognito_user_id:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Invalid token - missing user email or ID"})
                }

            # Get additional user attributes from Cognito
            try:
                cognito_response = cognito_client.admin_get_user(
                    UserPoolId=USER_POOL_ID,
                    Username=cognito_user_id
                )
                
                # Extract user attributes from Cognito
                user_attributes = {}
                for attr in cognito_response.get('UserAttributes', []):
                    user_attributes[attr['Name']] = attr['Value']
                
            except Exception as cognito_error:
                print(f"Failed to fetch user from Cognito: {str(cognito_error)}")
                # Continue with basic info from token
                user_attributes = {}

            # Check if user already exists in DynamoDB
            response = table.scan(
                FilterExpression="email = :email",
                ExpressionAttributeValues={":email": user_email}
            )

            existing_user = response.get("Items", [])
            
            if existing_user:
                # User exists, update with Cognito sync timestamp and any missing fields
                user_id = existing_user[0]["userid"]
                existing_data = existing_user[0]
                
                # Prepare update expression for sync
                update_expression_parts = ["cognitoSyncTimestamp = :timestamp", "cognitoUserId = :cognitoUserId"]
                expression_values = {
                    ":timestamp": datetime.datetime.utcnow().isoformat(),
                    ":cognitoUserId": cognito_user_id
                }
                
                # Update default names if they're still the generic defaults
                if (existing_data.get("fname", "") in ["", "User"] or 
                    existing_data.get("lname", "") in ["", "User"]):
                    
                    # Try to get better names from Cognito attributes
                    cognito_first_name = user_attributes.get('given_name', user_attributes.get('custom:firstName', ''))
                    cognito_last_name = user_attributes.get('family_name', user_attributes.get('custom:lastName', ''))
                    
                    if cognito_first_name:
                        update_expression_parts.append("#fname = :fname")
                        expression_values[":fname"] = cognito_first_name
                        
                    if cognito_last_name:
                        update_expression_parts.append("#lname = :lname") 
                        expression_values[":lname"] = cognito_last_name
                
                # Update user type and institution if they have Cognito custom attributes
                cognito_user_type = user_attributes.get('custom:userType', '')
                cognito_institution = user_attributes.get('custom:institution', '')
                
                if cognito_user_type and cognito_user_type != existing_data.get("userType", ""):
                    update_expression_parts.append("userType = :userType")
                    expression_values[":userType"] = cognito_user_type
                    
                if cognito_institution and not existing_data.get("institution", ""):
                    update_expression_parts.append("institution = :institution")
                    expression_values[":institution"] = cognito_institution
                
                # Build update expression
                update_expression = "SET " + ", ".join(update_expression_parts)
                update_params = {
                    "Key": {"userid": user_id},
                    "UpdateExpression": update_expression,
                    "ExpressionAttributeValues": expression_values
                }
                
                # Add attribute names if needed
                if any("#fname" in part or "#lname" in part for part in update_expression_parts):
                    update_params["ExpressionAttributeNames"] = {}
                    if "#fname" in update_expression:
                        update_params["ExpressionAttributeNames"]["#fname"] = "fname"
                    if "#lname" in update_expression:
                        update_params["ExpressionAttributeNames"]["#lname"] = "lname"
                
                table.update_item(**update_params)
                
                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": "User profile synced successfully",
                        "userid": user_id,
                        "action": "updated",
                        "cognitoUserId": cognito_user_id,
                        "updatedFields": list(expression_values.keys())
                    })
                }
            else:
                # User doesn't exist, create new profile with intelligent defaults
                user_id = str(uuid.uuid4())
                creation_time = datetime.datetime.utcnow().isoformat()
                
                # Extract info from Cognito attributes with intelligent fallbacks
                first_name = user_attributes.get('given_name', user_attributes.get('custom:firstName', ''))
                last_name = user_attributes.get('family_name', user_attributes.get('custom:lastName', ''))
                user_type = user_attributes.get('custom:userType', 'Student')
                institution = user_attributes.get('custom:institution', '')
                
                # If no names from Cognito, generate from email
                if not first_name:
                    email_prefix = user_email.split('@')[0]
                    first_name = email_prefix.replace('.', ' ').replace('_', ' ').title()
                    
                if not last_name:
                    last_name = "User"  # Default last name
                
                # Create new user profile with intelligent defaults
                table.put_item(
                    Item={
                        "userid": user_id,
                        "email": user_email,
                        "fname": first_name,
                        "lname": last_name,
                        "userType": user_type,
                        "institution": institution,
                        "acreation": creation_time,
                        "cognitoSyncTimestamp": creation_time,
                        "cognitoUserId": cognito_user_id,
                        "profileComplete": False,
                        "signupMethod": "cognito_sync",
                        "needsProfileCompletion": True
                    }
                )
                
                return {
                    "statusCode": 201,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": "User profile created successfully via sync",
                        "userid": user_id,
                        "action": "created",
                        "cognitoUserId": cognito_user_id,
                        "profileData": {
                            "firstName": first_name,
                            "lastName": last_name,
                            "userType": user_type,
                            "institution": institution,
                            "needsCompletion": True
                        }
                    })
                }

        # Method not allowed
        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"})
        }

    except Exception as e:
        print(f"Error in sync_cognito_user: {str(e)}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }