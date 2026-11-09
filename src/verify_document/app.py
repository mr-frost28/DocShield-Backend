import json
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
from datetime import datetime

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST,PUT",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

# Initialize AWS services
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
USERS_TABLE_NAME = "evidyavault-users"
BUCKET_NAME = "evidyavault-storage"

users_table = dynamodb.Table(USERS_TABLE_NAME)

def decimal_default(obj):
    """Helper function to handle Decimal objects in JSON serialization"""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError

def check_verifier_access(user_email):
    """Check if user has verifier role"""
    try:
        response = users_table.scan(
            FilterExpression=Attr('email').eq(user_email),
            ProjectionExpression="email, profileType, designation"
        )
        items = response.get("Items", [])
        
        if not items:
            return False, "User not found"
        
        user = items[0]
        profile_type = user.get("profileType", "").lower()
        designation = user.get("designation", "").lower()
        
        # Define verifier criteria (customize as needed)
        verifier_profiles = ["admin", "faculty", "verifier"]
        verifier_designations = ["professor", "dean", "academic_coordinator", "verifier"]
        
        is_verifier = (
            profile_type in verifier_profiles or 
            designation in verifier_designations or
            "verifier" in profile_type or
            "admin" in profile_type
        )
        
        if not is_verifier:
            return False, "Access denied: Verifier role required"
            
        return True, "Access granted"
        
    except Exception as e:
        return False, f"Error checking verifier access: {str(e)}"

def get_s3_key_from_document_id(document_id):
    """Convert document ID back to S3 key"""
    # Reverse the transformation done in verification_documents
    # documentId was created as: key.replace('/', '_').replace('.', '_')
    # This is a simplified approach - you might need more sophisticated logic
    try:
        # List all objects and find matching one
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=BUCKET_NAME)
        
        for page in page_iterator:
            for obj in page.get('Contents', []):
                key = obj['Key']
                if key.endswith("/"):
                    continue
                
                # Generate the same document ID format
                generated_id = key.replace('/', '_').replace('.', '_')
                if generated_id == document_id:
                    return key
        
        return None
    except Exception as e:
        return None

def update_document_verification_status(s3_key, new_status, verifier_email, comments=""):
    """Update document verification status using S3 tags"""
    try:
        # Get current tags
        try:
            current_tags_response = s3.get_object_tagging(Bucket=BUCKET_NAME, Key=s3_key)
            current_tags = {tag['Key']: tag['Value'] for tag in current_tags_response.get('TagSet', [])}
        except:
            current_tags = {}
        
        # Update verification tags
        current_tags.update({
            'verification_status': new_status,
            'verified_by': verifier_email,
            'verification_date': datetime.utcnow().isoformat(),
            'verifier_comments': comments
        })
        
        # Convert back to TagSet format
        tag_set = [{'Key': k, 'Value': str(v)} for k, v in current_tags.items()]
        
        # Update S3 object tags
        s3.put_object_tagging(
            Bucket=BUCKET_NAME,
            Key=s3_key,
            Tagging={'TagSet': tag_set}
        )
        
        return True, "Document verification status updated successfully"
        
    except Exception as e:
        return False, f"Error updating verification status: {str(e)}"

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

        if method in ["POST", "PUT"]:
            # Parse request body
            body = event.get("body", "{}")
            try:
                request_data = json.loads(body)
            except:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Invalid JSON in request body"}, default=decimal_default)
                }
            
            # Extract required fields
            document_id = request_data.get("documentId")
            new_status = request_data.get("status", "Verified")  # Default to Verified
            verifier_email = request_data.get("verifierEmail")
            comments = request_data.get("comments", "")
            
            # Validate required fields
            if not document_id:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing documentId"}, default=decimal_default)
                }
            
            if not verifier_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing verifierEmail"}, default=decimal_default)
                }
            
            # Validate status value
            valid_statuses = ["Verified", "Rejected", "Pending Verification"]
            if new_status not in valid_statuses:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
                    }, default=decimal_default)
                }
            
            # Check if user has verifier access
            has_access, access_message = check_verifier_access(verifier_email)
            if not has_access:
                return {
                    "statusCode": 403,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": access_message}, default=decimal_default)
                }
            
            # Get S3 key from document ID
            s3_key = get_s3_key_from_document_id(document_id)
            if not s3_key:
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Document not found"}, default=decimal_default)
                }
            
            # Update verification status
            success, message = update_document_verification_status(
                s3_key, new_status, verifier_email, comments
            )
            
            if not success:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": message}, default=decimal_default)
                }
            
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": message,
                    "documentId": document_id,
                    "status": new_status,
                    "verifiedBy": verifier_email,
                    "verificationDate": datetime.utcnow().isoformat()
                }, default=decimal_default)
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