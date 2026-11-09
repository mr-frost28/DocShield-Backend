import json
import boto3
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def get_content_type(filename):
    """Determine content type from filename extension"""
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
        'gif': 'image/gif',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'xls': 'application/vnd.ms-excel',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    }
    
    return content_types.get(ext, 'application/octet-stream')

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,GET",
    "Access-Control-Allow-Headers": "Content-Type"
}

BUCKET_NAME = "docshield-storage"
s3 = boto3.client("s3")

def get_document_verification_status(s3_key):
    """Get verification status from S3 object tags"""
    try:
        response = s3.get_object_tagging(Bucket=BUCKET_NAME, Key=s3_key)
        tags = {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
        
        # Get verification status from tags
        verification_status = tags.get('verification_status', 'Pending Verification')
        verifier_comments = tags.get('verifier_comments', '')
        verification_date = tags.get('verification_date', '')
        verified_by = tags.get('verified_by', tags.get('rejected_by', tags.get('revision_requested_by', tags.get('approved_by', ''))))
        
        logger.debug(f"Document: {s3_key} -> Status: {verification_status}")
        
        return {
            'status': verification_status,
            'verifierComments': verifier_comments,
            'verificationDate': verification_date,
            'verifiedBy': verified_by
        }
        
    except Exception as e:
        logger.warning(f"Could not get tags for {s3_key}: {e}")
        return {
            'status': 'Pending Verification',
            'verifierComments': '',
            'verificationDate': '',
            'verifiedBy': ''
        }

def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "")
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }
        if method == "GET":
            params = event.get("queryStringParameters", {}) or {}
            userEmail = params.get("userEmail")
            
            if not userEmail:
                logger.warning("Missing userEmail parameter in request")
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing userEmail parameter"})
                }
            
            logger.info(f"Fetching document list for user: {userEmail}")
            prefix = f"{userEmail}/"
            paginator = s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=BUCKET_NAME, Prefix=prefix)
            documents = []
            for page in page_iterator:
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    if key.endswith("/"):
                        continue  # skip folder keys
                    title = key.split("/")[-1]
                    file_type = title.split(".")[-1] if "." in title else "Unknown"
                    upload_date = obj.get('LastModified')
                    upload_date_str = upload_date.isoformat() if upload_date else None
                    file_size = obj.get('Size', 0)  # Get file size in bytes
                    
                    # Get actual verification status from S3 tags
                    verification_info = get_document_verification_status(key)
                    
                    # Generate document ID for consistency with other APIs
                    document_id = key.replace('/', '_').replace('.', '_').replace(' ', '_')
                    
                    documents.append({
                        "documentId": document_id,
                        "title": title,
                        "fileName": title,  # Add fileName for consistency
                        "type": file_type,
                        "contentType": get_content_type(title),
                        "uploadDate": upload_date_str,
                        "status": verification_info['status'],
                        "verifierComments": verification_info['verifierComments'],
                        "verificationDate": verification_info['verificationDate'],
                        "verifiedBy": verification_info['verifiedBy'],
                        "s3Key": key,
                        "size": format_file_size(file_size),  # Human-readable size
                        "sizeBytes": file_size,  # File size in bytes
                        "uploadedBy": userEmail  # Add for clarity
                    })
            # Add summary statistics
            total_documents = len(documents)
            status_counts = {}
            for doc in documents:
                status = doc['status']
                status_counts[status] = status_counts.get(status, 0) + 1
            
            logger.info(f"Successfully retrieved {total_documents} documents for user: {userEmail}")
            logger.info(f"Status breakdown: {status_counts}")
            
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "success": True,
                    "documents": documents,
                    "totalDocuments": total_documents,
                    "statusSummary": status_counts,
                    "userEmail": userEmail,
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": f"Retrieved {total_documents} documents successfully"
                })
            }
        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed"})
        }
    except Exception as e:
        logger.error(f"Error in lambda handler: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "success": False,
                "error": str(e),
                "message": "Internal server error occurred while fetching document list",
                "timestamp": datetime.utcnow().isoformat()
            })
        }
