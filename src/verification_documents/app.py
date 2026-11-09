import json
import logging
from decimal import Decimal
from datetime import datetime

try:
    import boto3
    from boto3.dynamodb.conditions import Attr
except ImportError as e:
    print(f"Error importing AWS SDK: {e}")
    # For local development, you might want to mock these
    boto3 = None

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,GET",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AWS services
try:
    s3 = boto3.client('s3') if boto3 else None
    dynamodb = boto3.resource('dynamodb') if boto3 else None
    BUCKET_NAME = "docshield-storage"
    USERS_TABLE_NAME = "docshield-users"
    
    if boto3 and dynamodb:
        users_table = dynamodb.Table(USERS_TABLE_NAME)
    else:
        users_table = None
        
except Exception as e:
    logger.error(f"Failed to initialize AWS services: {e}")
    s3 = None
    dynamodb = None
    users_table = None

def decimal_default(obj):
    """Helper function to handle Decimal objects in JSON serialization"""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError

def check_verifier_access(user_email):
    """Check if user has verifier role by querying database for userRole == 'Verifier'"""
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
            # Use Scan with FilterExpression like other Lambda functions
            # since 'email' is not the primary key, 'userid' is the primary key
            response = users_table.scan(
                FilterExpression=Attr('email').eq(user_email),
                ProjectionExpression="email, userRole"
            )
            items = response.get("Items", [])
            
            if not items:
                logger.warning(f"User not found in database: {user_email}")
                return False, "User not found in database"
            
            user = items[0]
            user_role = user.get("userRole", "")
            
            logger.info(f"User found in database - userRole: {user_role}")
            
            # Check if userRole is exactly "Verifier"
            if user_role == "Verifier":
                logger.info(f"Access granted for verifier: {user_email}")
                return True, "Access granted (verified from database)"
            else:
                logger.warning(f"Access denied for user {user_email}: userRole is '{user_role}', expected 'Verifier'")
                return False, "Access denied: User role is not 'Verifier'"
                
        except Exception as db_error:
            logger.error(f"Database error while checking verifier access: {db_error}")
            return False, f"Database error: {str(db_error)}"
        
    except Exception as e:
        logger.error(f"Error checking verifier access: {e}")
        return False, f"Error checking verifier access: {str(e)}"

def get_all_documents_by_status(status_filter):
    """Get all documents across all users filtered by verification status - for verifiers"""
    try:
        logger.info(f"Fetching all documents with status filter: {status_filter}")
        documents = []
        
        # Check if S3 client is available
        if not s3 or not boto3:
            logger.error("S3 client not available")
            return {
                "documents": [],
                "message": "AWS S3 service not available",
                "error": "S3 client initialization failed"
            }
        
        try:
            # List all objects in the bucket
            logger.info("Listing all objects in bucket for verification")
            
            paginator = s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(
                Bucket=BUCKET_NAME,
                MaxKeys=500  # Increased limit for verifiers to see all documents
            )
            
            total_processed = 0
            for page in page_iterator:
                contents = page.get('Contents', [])
                logger.info(f"Processing page with {len(contents)} objects")
                
                for obj in contents:
                    key = obj['Key']
                    total_processed += 1
                    
                    # Skip folder keys and empty objects
                    if key.endswith("/") or obj.get('Size', 0) == 0:
                        logger.debug(f"Skipping folder/empty object: {key}")
                        continue
                    
                    # Extract user email from S3 key path
                    path_parts = key.split('/')
                    if len(path_parts) < 2:
                        logger.debug(f"Skipping invalid key structure: {key}")
                        continue
                    
                    uploaded_by = path_parts[0]  # First part is user email
                    file_name = path_parts[-1]  # Last part is filename
                    
                    # Get object tags to check verification status
                    verification_status = 'Pending Verification'  # Default
                    verifier_comments = ""
                    verification_date = ""
                    verified_by = ""
                    
                    try:
                        tags_response = s3.get_object_tagging(Bucket=BUCKET_NAME, Key=key)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
                        verification_status = tags.get('verification_status', 'Pending Verification')
                        verifier_comments = tags.get('verifier_comments', '')
                        verification_date = tags.get('verification_date', '')
                        verified_by = tags.get('verified_by', tags.get('rejected_by', tags.get('revision_requested_by', tags.get('approved_by', ''))))
                        logger.debug(f"Retrieved tags for {key}: {verification_status}")
                    except Exception as tag_error:
                        logger.warning(f"Could not retrieve tags for {key}: {tag_error}")
                    
                    # Filter by status if specified
                    if status_filter and verification_status != status_filter:
                        logger.debug(f"Skipping {key} due to status filter: {verification_status} != {status_filter}")
                        continue
                    
                    # Generate pre-signed URL for viewing
                    file_url = "#"  # Default fallback
                    try:
                        file_url = s3.generate_presigned_url(
                            'get_object',
                            Params={'Bucket': BUCKET_NAME, 'Key': key},
                            ExpiresIn=7200  # URL expires in 2 hours for verifiers
                        )
                        logger.debug(f"Generated presigned URL for {key}")
                    except Exception as url_error:
                        logger.warning(f"Could not generate presigned URL for {key}: {url_error}")
                    
                    # Format upload date
                    upload_date = obj.get('LastModified')
                    upload_date_str = upload_date.strftime('%Y-%m-%d %H:%M:%S') if upload_date else "Unknown"
                    
                    # Generate unique document ID
                    document_id = key.replace('/', '_').replace('.', '_').replace(' ', '_')
                    
                    document = {
                        "documentId": document_id,
                        "fileName": file_name,
                        "uploadedBy": uploaded_by,
                        "status": verification_status,
                        "fileUrl": file_url,
                        "uploadDate": upload_date_str,
                        "fileSize": obj.get('Size', 0),
                        "s3Key": key,
                        "verifierComments": verifier_comments,
                        "verificationDate": verification_date,
                        "verifiedBy": verified_by,
                        "contentType": _get_content_type_from_filename(file_name)
                    }
                    
                    documents.append(document)
                    logger.debug(f"Added document: {file_name} by {uploaded_by}")
                    
            logger.info(f"Processed {total_processed} objects, found {len(documents)} matching documents")
                    
        except Exception as e:
            error_message = str(e)
            logger.error(f"S3 operation failed: {error_message}")
            
            # Handle specific AWS errors
            if "AccessDenied" in error_message:
                return {
                    "documents": [],
                    "message": "Access denied. Please check S3 permissions for the bucket.",
                    "error": "S3 ListBucket permission required"
                }
            elif "NoSuchBucket" in error_message:
                return {
                    "documents": [],
                    "message": f"Bucket '{BUCKET_NAME}' does not exist.",
                    "error": "S3 bucket not found"
                }
            elif "InvalidBucketName" in error_message:
                return {
                    "documents": [],
                    "message": "Invalid bucket name configuration.",
                    "error": "Invalid S3 bucket configuration"
                }
            else:
                # Re-raise unknown errors
                raise e
        
        # Sort by upload date (newest first) then by uploaded user
        try:
            documents.sort(key=lambda x: (
                datetime.strptime(x.get('uploadDate', '1970-01-01 00:00:00'), '%Y-%m-%d %H:%M:%S'),
                x.get('uploadedBy', '')
            ), reverse=True)
        except Exception as sort_error:
            logger.warning(f"Could not sort documents by date: {sort_error}")
            # Keep original order if sorting fails
        
        logger.info(f"Successfully retrieved {len(documents)} documents for verification")
        return {
            "documents": documents,
            "message": f"Found {len(documents)} documents" + (f" with status '{status_filter}'" if status_filter else " for verification")
        }
        
    except Exception as e:
        logger.error(f"Error fetching documents: {e}")
        raise Exception(f"Error fetching documents: {str(e)}")

def _get_content_type_from_filename(filename):
    """Helper function to determine content type from filename"""
    if not filename or '.' not in filename:
        return 'application/octet-stream'
    
    ext = filename.lower().split('.')[-1]
    content_types = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif'
    }
    
    return content_types.get(ext, 'application/octet-stream')



def lambda_handler(event, context):
    """
    AWS Lambda handler for verification documents API
    Supports GET requests to retrieve documents for verification
    """
    # Log the incoming request for debugging
    logger.info(f"Lambda invoked with method: {event.get('httpMethod', 'UNKNOWN')}")
    logger.debug(f"Full event: {json.dumps(event, default=str)}")
    
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight
        if method == "OPTIONS":
            logger.info("Handling CORS preflight request")
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"}, default=decimal_default)
            }

        if method == "GET":
            logger.info("Processing GET request for document verification")
            
            # Get query parameters with validation
            params = event.get("queryStringParameters", {}) or {}
            verifier_email = params.get("userEmail")
            status_filter = params.get("status")
            
            # Log request parameters (excluding sensitive data)
            logger.info(f"Request params - verifier: {verifier_email}, status: {status_filter}")
            
            # Validate required parameters
            if not verifier_email:
                logger.warning("Missing userEmail parameter in request")
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing userEmail parameter"}, default=decimal_default)
                }
            
            # Set default status filter if not provided
            if not status_filter:
                # Don't filter by default - show all pending statuses
                status_filter = None  # Show all documents by default
                logger.info(f"No status filter provided, showing all documents")
            
            # Check if user has verifier access
            logger.info(f"Checking verifier access for: {verifier_email}")
            has_access, access_message = check_verifier_access(verifier_email)
            if not has_access:
                logger.warning(f"Access denied for user {verifier_email}: {access_message}")
                return {
                    "statusCode": 403,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": access_message}, default=decimal_default)
                }
            
            logger.info(f"Access granted for verifier: {verifier_email}")
            
            try:
                # Get all documents for verification (verifiers see all documents)
                logger.info(f"Fetching all documents for verification with status: {status_filter}")
                result = get_all_documents_by_status(status_filter)
                
                # Handle cases where result contains error information
                if isinstance(result, dict) and "error" in result:
                    logger.warning(f"Document fetch returned error: {result.get('error')}")
                    error_status = 403 if "permission" in result.get("error", "").lower() else 500
                    return {
                        "statusCode": error_status,
                        "headers": CORS_HEADERS,
                        "body": json.dumps(result, default=decimal_default)
                    }
                
                documents = result.get("documents", [])
                message = result.get("message", "")
                
                logger.info(f"Successfully retrieved {len(documents)} documents")
                
                # Prepare response with additional metadata
                response_data = {
                    "documents": documents,
                    "count": len(documents),
                    "status_filter": status_filter,
                    "verifierEmail": verifier_email,
                    "message": message,
                    "timestamp": datetime.utcnow().isoformat(),
                    "available_statuses": [
                        "All Documents",  # No filter
                        "Pending Verification", 
                        "Verified", 
                        "Rejected", 
                        "Revision Required",
                        "Approved with Conditions"
                    ]
                }
                
                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps(response_data, default=decimal_default)
                }
                
            except Exception as e:
                logger.error(f"Error processing document request: {e}", exc_info=True)
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "error": f"Error accessing documents: {str(e)}",
                        "timestamp": datetime.utcnow().isoformat()
                    }, default=decimal_default)
                }

        # Handle unsupported HTTP methods
        logger.warning(f"Unsupported HTTP method: {method}")
        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "error": f"Method {method} not allowed",
                "supported_methods": ["GET", "OPTIONS"]
            }, default=decimal_default)
        }

    except Exception as e:
        # Log unexpected errors with full traceback
        logger.error(f"Unexpected error in lambda handler: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "error": "Internal server error",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }, default=decimal_default)
        }