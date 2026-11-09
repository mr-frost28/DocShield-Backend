import json
import logging
from decimal import Decimal
from datetime import datetime

try:
    import boto3
    from boto3.dynamodb.conditions import Attr
except ImportError as e:
    print(f"Error importing AWS SDK: {e}")
    boto3 = None

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AWS services
try:
    dynamodb = boto3.resource('dynamodb') if boto3 else None
    s3 = boto3.client('s3') if boto3 else None
    USERS_TABLE_NAME = "docshield-users"
    BUCKET_NAME = "docshield-storage"
    
    if boto3 and dynamodb:
        users_table = dynamodb.Table(USERS_TABLE_NAME)
    else:
        users_table = None
        
except Exception as e:
    logger.error(f"Failed to initialize AWS services: {e}")
    dynamodb = None
    s3 = None
    users_table = None

def decimal_default(obj):
    """Helper function to handle Decimal objects in JSON serialization"""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError

def check_verifier_access(user_email):
    """Check if user has verifier role by querying database - supports multiple role fields"""
    try:
        logger.info(f"Checking verifier access for user: {user_email}")
        
        if not user_email or user_email.strip() == "":
            logger.warning("Invalid user email provided")
            return False, "Invalid user email"
        
        # Basic email validation
        if "@" not in user_email or "." not in user_email:
            logger.warning(f"Invalid email format: {user_email}")
            return False, "Invalid email format"
        
        # Check if database is available
        if not users_table or not boto3:
            logger.error("Database not available")
            return False, "Database service not available"
        
        try:
            # Use Scan with FilterExpression to find user by email
            # Get all relevant fields for role checking
            response = users_table.scan(
                FilterExpression=Attr('email').eq(user_email),
                ProjectionExpression="email, userRole, profileType, designation"
            )
            items = response.get("Items", [])
            
            if not items:
                logger.warning(f"User not found in database: {user_email}")
                return False, "User not found in database"
            
            user = items[0]
            user_role = user.get("userRole", "")
            profile_type = user.get("profileType", "").lower()
            designation = user.get("designation", "").lower()
            
            logger.info(f"User found - userRole: '{user_role}', profileType: '{profile_type}', designation: '{designation}'")
            
            # Check multiple possible verifier role indicators
            # 1. Direct userRole check
            if user_role == "Verifier":
                logger.info(f"Access granted via userRole: {user_email}")
                return True, "Access granted (userRole = Verifier)"
            
            # 2. Profile type based check (from verify_document pattern)
            verifier_profiles = ["admin", "faculty", "verifier"]
            if profile_type in verifier_profiles:
                logger.info(f"Access granted via profileType '{profile_type}': {user_email}")
                return True, f"Access granted (profileType = {profile_type})"
            
            # 3. Designation based check
            verifier_designations = ["professor", "dean", "academic_coordinator", "verifier"]
            if designation in verifier_designations:
                logger.info(f"Access granted via designation '{designation}': {user_email}")
                return True, f"Access granted (designation = {designation})"
            
            # 4. Check for 'verifier' or 'admin' keywords in any field
            if ("verifier" in profile_type or "admin" in profile_type or
                "verifier" in designation or "admin" in designation or
                "verifier" in user_role.lower() or "admin" in user_role.lower()):
                logger.info(f"Access granted via keyword match: {user_email}")
                return True, "Access granted (contains verifier/admin keyword)"
            
            # If none of the above match, deny access
            logger.warning(f"Access denied - no verifier role found for {user_email}")
            logger.warning(f"Available fields: userRole='{user_role}', profileType='{profile_type}', designation='{designation}'")
            return False, "Access denied: No verifier role found"
                
        except Exception as db_error:
            logger.error(f"Database error while checking verifier access: {db_error}")
            return False, f"Database error: {str(db_error)}"
        
    except Exception as e:
        logger.error(f"Error checking verifier access: {e}")
        return False, f"Error checking verifier access: {str(e)}"

def get_s3_key_from_filename_and_owner_email(filename, owner_email):
    """Construct S3 key from filename and document owner's email (not verifier's email)"""
    try:
        logger.info(f"=== DOCUMENT LOOKUP BY OWNER EMAIL ===")
        logger.info(f"Filename: '{filename}'")
        logger.info(f"Document Owner Email: '{owner_email}'")
        
        if not s3 or not boto3:
            logger.error("S3 client not available")
            return None
        
        if not filename or not filename.strip():
            logger.warning("Invalid filename provided")
            return None
            
        if not owner_email or not owner_email.strip():
            logger.warning("Invalid owner email provided")
            return None
        
        # Construct S3 key using OWNER's email (not verifier's email)
        s3_key = f"{owner_email}/{filename}"
        logger.info(f"Constructed S3 key: '{s3_key}'")
        
        # Verify the key exists in S3
        try:
            logger.info(f"Attempting S3 head_object call...")
            logger.info(f"Bucket: '{BUCKET_NAME}'")
            logger.info(f"Key: '{s3_key}'")
            
            response = s3.head_object(Bucket=BUCKET_NAME, Key=s3_key)
            logger.info(f"SUCCESS: Document found at S3 key: '{s3_key}'")
            logger.info(f"S3 object details: Size={response.get('ContentLength', 0)} bytes, LastModified={response.get('LastModified', 'unknown')}")
            return s3_key
        except Exception as e:
            logger.error(f"S3 head_object FAILED for key '{s3_key}'")
            logger.error(f"Bucket: '{BUCKET_NAME}'")
            logger.error(f"Error: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            
            if hasattr(e, 'response'):
                error_code = e.response.get('Error', {}).get('Code', 'unknown')
                error_message = e.response.get('Error', {}).get('Message', 'unknown')
                logger.error(f"S3 Error code: {error_code}")
                logger.error(f"S3 Error message: {error_message}")
                
                if error_code == 'NoSuchKey':
                    logger.error("The S3 key does not exist - file is not at this location")
                elif error_code == 'NoSuchBucket':
                    logger.error(f"The bucket '{BUCKET_NAME}' does not exist")
                elif error_code == 'AccessDenied':
                    logger.error("Access denied - check Lambda execution role S3 permissions")
                elif error_code == 'InvalidBucketName':
                    logger.error(f"Invalid bucket name: '{BUCKET_NAME}'")
            
            return None
        
        return None
        
    except Exception as e:
        logger.error(f"Error constructing S3 key from filename '{filename}' and owner email '{owner_email}': {e}")
        return None

def perform_document_action(s3_key, action, verifier_email, reason="", additional_data=None):
    """Perform various document actions (verify, reject, request revision, etc.) with comprehensive logging"""
    try:
        logger.info(f"Performing action '{action}' on document '{s3_key}' by verifier '{verifier_email}'")
        
        if not s3 or not boto3:
            logger.error("S3 client not available")
            return False, "S3 service not available"
        
        # Validate inputs
        if not s3_key or not s3_key.strip():
            logger.error("Invalid S3 key provided")
            return False, "Invalid document key"
        
        if not action or action not in ["verify", "reject", "request_revision", "approve_with_conditions"]:
            logger.error(f"Invalid action provided: {action}")
            return False, f"Invalid action: {action}"
        
        if not verifier_email or not verifier_email.strip():
            logger.error("Invalid verifier email provided")
            return False, "Invalid verifier email"
        
        # Check if document exists
        try:
            s3.head_object(Bucket=BUCKET_NAME, Key=s3_key)
            logger.info(f"Document exists in S3: {s3_key}")
        except Exception as e:
            logger.error(f"Document not found in S3: {s3_key}, error: {e}")
            return False, "Document not found"
        
        # Get current tags
        current_tags = {}
        try:
            current_tags_response = s3.get_object_tagging(Bucket=BUCKET_NAME, Key=s3_key)
            current_tags = {tag['Key']: tag['Value'] for tag in current_tags_response.get('TagSet', [])}
            logger.debug(f"Retrieved existing tags for {s3_key}: {list(current_tags.keys())}")
        except Exception as tag_error:
            logger.warning(f"Could not retrieve existing tags for {s3_key}: {tag_error}")
            # Continue with empty tags
        
        # Update tags based on action
        timestamp = datetime.utcnow().isoformat()
        
        if action == "verify":
            current_tags.update({
                'verification_status': 'Verified',
                'verified_by': verifier_email,
                'verification_date': timestamp,
                'verifier_comments': reason or 'Document approved by verifier'
            })
            status_message = "Document verified successfully"
            
        elif action == "reject":
            current_tags.update({
                'verification_status': 'Rejected',
                'rejected_by': verifier_email,
                'rejection_date': timestamp,
                'rejection_reason': reason or 'Document does not meet requirements',
                'verifier_comments': reason or 'Document rejected by verifier'
            })
            status_message = "Document rejected"
            
        elif action == "request_revision":
            current_tags.update({
                'verification_status': 'Revision Required',
                'revision_requested_by': verifier_email,
                'revision_request_date': timestamp,
                'revision_comments': reason or 'Please revise and resubmit',
                'verifier_comments': reason or 'Revision requested by verifier'
            })
            status_message = "Revision requested"
            
        elif action == "approve_with_conditions":
            conditions = additional_data.get('conditions', '') if additional_data else ''
            current_tags.update({
                'verification_status': 'Approved with Conditions',
                'approved_by': verifier_email,
                'approval_date': timestamp,
                'approval_conditions': conditions,
                'verifier_comments': reason or 'Approved with conditions by verifier'
            })
            status_message = "Document approved with conditions"
        
        # Convert back to TagSet format (S3 tag values must be strings)
        tag_set = [{'Key': str(k), 'Value': str(v)} for k, v in current_tags.items()]
        
        # Update S3 object tags
        try:
            s3.put_object_tagging(
                Bucket=BUCKET_NAME,
                Key=s3_key,
                Tagging={'TagSet': tag_set}
            )
            logger.info(f"Successfully updated tags for {s3_key} with action {action}")
        except Exception as tag_update_error:
            logger.error(f"Failed to update tags for {s3_key}: {tag_update_error}")
            return False, f"Failed to update document status: {str(tag_update_error)}"
        
        logger.info(f"Document action completed: {status_message}")
        return True, status_message
        
    except Exception as e:
        logger.error(f"Error performing document action '{action}' on '{s3_key}': {e}", exc_info=True)
        return False, f"Error performing document action: {str(e)}"

def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "").upper() if event.get("httpMethod") else ""

        # Handle CORS preflight
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"}, default=decimal_default)
            }

        if method == "POST":
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
            filename = request_data.get("fileName")  # New: direct filename from S3
            action = request_data.get("action")  # verify, reject, request_revision, approve_with_conditions
            verifier_email = request_data.get("verifierEmail")
            owner_email = request_data.get("ownerEmail") or request_data.get("uploadedBy")  # Document owner's email
            reason = request_data.get("reason", "")
            additional_data = request_data.get("additionalData", {})
            
            # Debug: Log the incoming request data
            logger.info(f"=== INCOMING REQUEST DEBUG ===")
            logger.info(f"Filename received: '{filename}'")
            logger.info(f"Action: '{action}'")
            logger.info(f"Verifier Email: '{verifier_email}'")
            logger.info(f"Owner Email: '{owner_email}'")
            logger.info(f"Reason: '{reason}'")
            logger.info(f"Full request data keys: {list(request_data.keys())}")
            logger.info(f"Full request data: {request_data}")
            logger.info(f"Raw request body preview: {body[:200]}...")  # First 200 chars
            
            # Validate required fields
            if not filename:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing fileName"}, default=decimal_default)
                }
            
            if not action:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing action"}, default=decimal_default)
                }
            
            if not verifier_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing verifierEmail"}, default=decimal_default)
                }
            
            if not owner_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing ownerEmail or uploadedBy field - document owner's email is required"}, default=decimal_default)
                }
            
            # Validate action
            valid_actions = ["verify", "reject", "request_revision", "approve_with_conditions"]
            if action not in valid_actions:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"
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
            
            # Get S3 key from filename and document owner's email
            s3_key = request_data.get("s3Key")  # Check if S3 key is provided directly
            
            if not s3_key:
                logger.info(f"No direct S3 key provided, constructing from filename and owner email")
                
                # Skip S3 connectivity test to avoid ListBucket permission requirement
                logger.info(f"=== S3 DIRECT ACCESS MODE ===")
                logger.info(f"S3 client available: {s3 is not None}")
                logger.info(f"Bucket name: '{BUCKET_NAME}'")
                logger.info(f"Skipping ListBucket test - using direct head_object instead")
                
                # Construct S3 key from filename and OWNER'S email (not verifier's email)
                s3_key = get_s3_key_from_filename_and_owner_email(filename, owner_email)
                
            if not s3_key:
                logger.error(f"Could not find document with filename: '{filename}' for owner: '{owner_email}'")
                
                # Perform additional diagnostics
                expected_key = f"{owner_email}/{filename}"
                diagnostic_info = {
                    "error": "Document not found", 
                    "fileName": filename,
                    "ownerEmail": owner_email,
                    "verifierEmail": verifier_email,
                    "expectedS3Key": expected_key,
                    "bucket": BUCKET_NAME,
                    "diagnostics": {}
                }
                
                # Test 1: Try direct S3 head_object call
                try:
                    direct_response = s3.head_object(Bucket=BUCKET_NAME, Key=expected_key)
                    diagnostic_info["diagnostics"]["directHeadObject"] = {
                        "success": True,
                        "size": direct_response.get('ContentLength', 0),
                        "lastModified": str(direct_response.get('LastModified', ''))
                    }
                    logger.error(f"STRANGE: Direct head_object succeeded but function failed!")
                except Exception as direct_error:
                    diagnostic_info["diagnostics"]["directHeadObject"] = {
                        "success": False,
                        "error": str(direct_error),
                        "errorType": type(direct_error).__name__
                    }
                
                # Test 2: List objects with prefix for the OWNER (not verifier)
                try:
                    list_response = s3.list_objects_v2(
                        Bucket=BUCKET_NAME,
                        Prefix=f"{owner_email}/",
                        MaxKeys=20
                    )
                    objects = []
                    for obj in list_response.get('Contents', []):
                        objects.append({
                            "key": obj['Key'],
                            "size": obj.get('Size', 0),
                            "filename": obj['Key'].split('/')[-1],
                            "lastModified": obj.get('LastModified', '').isoformat() if obj.get('LastModified') else ''
                        })
                    
                    diagnostic_info["diagnostics"]["listObjects"] = {
                        "success": True,
                        "objectCount": len(objects),
                        "objects": objects,
                        "searchedPrefix": f"{owner_email}/"
                    }
                    
                    # Also check for similar filenames
                    target_filename = filename.lower()
                    similar_files = []
                    for obj in objects:
                        obj_filename = obj['filename'].lower()
                        # Check for partial matches or similar names
                        if (target_filename in obj_filename or 
                            obj_filename in target_filename or
                            'aws' in obj_filename and 'aws' in target_filename or
                            'certificate' in obj_filename and 'certificate' in target_filename):
                            similar_files.append(obj)
                    
                    if similar_files:
                        diagnostic_info["diagnostics"]["similarFiles"] = similar_files
                        
                except Exception as list_error:
                    diagnostic_info["diagnostics"]["listObjects"] = {
                        "success": False,
                        "error": str(list_error),
                        "errorType": type(list_error).__name__
                    }
                
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps(diagnostic_info, default=decimal_default)
                }
            
            logger.info(f"Using S3 key: '{s3_key}' for filename: '{filename}'")
            
            # Perform the requested action
            success, message = perform_document_action(
                s3_key, action, verifier_email, reason, additional_data
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
                    "fileName": filename,
                    "ownerEmail": owner_email,
                    "s3Key": s3_key,
                    "action": action,
                    "performedBy": verifier_email,
                    "timestamp": datetime.utcnow().isoformat(),
                    "reason": reason
                }, default=decimal_default)
            }

        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method '{method or 'UNKNOWN'}' not allowed. Only POST requests are supported."}, default=decimal_default)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)}, default=decimal_default)
        }