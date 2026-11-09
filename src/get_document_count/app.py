import json
import boto3
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,GET",
    "Access-Control-Allow-Headers": "Content-Type"
}

BUCKET_NAME = "docshield-storage"
s3 = boto3.client("s3")

def get_document_verification_status(s3_key):
    """Get verification status from S3 object tags - returns full status and category"""
    try:
        response = s3.get_object_tagging(Bucket=BUCKET_NAME, Key=s3_key)
        tags = {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
        
        # Check for verification status
        verification_status = tags.get('verification_status', 'Pending Verification')
        
        # Debug logging
        logger.info(f"Document: {s3_key}")
        logger.info(f"All tags: {tags}")
        logger.info(f"Verification status tag: '{verification_status}'")
        
        # Map status to category for counting purposes
        if verification_status == 'Verified':
            logger.info(f"Status: VERIFIED for {s3_key}")
            return verification_status, 'verified'
        elif verification_status in ['Rejected', 'Revision Required', 'Approved with Conditions']:
            logger.info(f"Status: {verification_status.upper()} for {s3_key}")
            return verification_status, 'processed'  # Processed but not fully verified
        else:
            logger.info(f"Status: PENDING for {s3_key} (status was '{verification_status}')")
            return verification_status, 'pending'  # Default for pending verification
            
    except Exception as e:
        logger.warning(f"Could not get tags for {s3_key}: {e}")
        logger.info(f"Status: PENDING (no tags) for {s3_key}")
        return 'Pending Verification', 'pending'  # Default if tags can't be retrieved

def get_document_counts_with_verification_status(user_email):
    """Get document counts categorized by verification status"""
    try:
        logger.info(f"Getting document counts for user: {user_email}")
        
        prefix = f"{user_email}/"
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=BUCKET_NAME, Prefix=prefix)
        
        # Initialize counters - comprehensive status tracking
        counts = {
            'total': 0,
            'verified': 0,
            'pending': 0,
            'processed': 0,  # For rejected, revision required, approved with conditions
            'rejected': 0,
            'revision_required': 0,
            'approved_with_conditions': 0
        }
        
        # Track documents by status for detailed response
        documents_by_status = {
            'verified': [],
            'pending': [],
            'processed': [],
            'rejected': [],
            'revision_required': [],
            'approved_with_conditions': []
        }
        
        for page in page_iterator:
            for obj in page.get('Contents', []):
                s3_key = obj['Key']
                filename = s3_key.split('/')[-1]  # Extract filename
                
                # Skip if it's just a folder (ends with /)
                if s3_key.endswith('/'):
                    continue
                
                counts['total'] += 1
                
                # Get verification status (returns both full status and category)
                full_status, category = get_document_verification_status(s3_key)
                counts[category] += 1
                
                # Also count specific statuses
                if full_status == 'Rejected':
                    counts['rejected'] += 1
                elif full_status == 'Revision Required':
                    counts['revision_required'] += 1
                elif full_status == 'Approved with Conditions':
                    counts['approved_with_conditions'] += 1
                
                # Add to documents list for this status category
                document_info = {
                    'filename': filename,
                    's3Key': s3_key,
                    'size': obj.get('Size', 0),
                    'lastModified': obj.get('LastModified').isoformat() if obj.get('LastModified') else None,
                    'status': full_status,  # Store full status instead of category
                    'category': category  # Add category for grouping
                }
                documents_by_status[category].append(document_info)
                
                # Also add to specific status lists
                if full_status == 'Rejected':
                    documents_by_status['rejected'].append(document_info)
                elif full_status == 'Revision Required':
                    documents_by_status['revision_required'].append(document_info)
                elif full_status == 'Approved with Conditions':
                    documents_by_status['approved_with_conditions'].append(document_info)
                
                # Debug logging for each document
                logger.info(f"Processed document: {filename} -> Status: {full_status} (Category: {category})")
        
        logger.info(f"Document count summary for {user_email}: {counts}")
        
        return {
            'success': True,
            'counts': counts,
            'documents': documents_by_status
        }
        
    except Exception as e:
        logger.error(f"Error getting document counts for {user_email}: {e}")
        return {
            'success': False,
            'error': str(e)
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
            user_email = params.get("userEmail")
            include_details = params.get("includeDetails", "false").lower() == "true"
            
            if not user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing userEmail parameter"})
                }
            
            logger.info(f"Processing document count request for user: {user_email}")
            
            # Get enhanced document counts with verification status
            result = get_document_counts_with_verification_status(user_email)
            
            if not result['success']:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": result['error']})
                }
            
            # Prepare response - comprehensive status breakdown
            response_data = {
                "userEmail": user_email,
                "totalDocuments": result['counts']['total'],
                "verifiedDocuments": result['counts']['verified'],
                "pendingVerification": result['counts']['pending'],
                "processedDocuments": result['counts']['processed'],
                "rejectedDocuments": result['counts']['rejected'],
                "revisionRequiredDocuments": result['counts']['revision_required'],
                "approvedWithConditionsDocuments": result['counts']['approved_with_conditions'],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Add detailed document lists if requested or for debugging
            if include_details or True:  # Always include for now to debug
                response_data["documentDetails"] = result['documents']
            
            # Add summary statistics
            response_data["summary"] = {
                "verificationRate": round((result['counts']['verified'] / result['counts']['total']) * 100, 2) if result['counts']['total'] > 0 else 0,
                "pendingRate": round((result['counts']['pending'] / result['counts']['total']) * 100, 2) if result['counts']['total'] > 0 else 0,
                "processedRate": round((result['counts']['processed'] / result['counts']['total']) * 100, 2) if result['counts']['total'] > 0 else 0,
                "rejectionRate": round((result['counts']['rejected'] / result['counts']['total']) * 100, 2) if result['counts']['total'] > 0 else 0
            }
            
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps(response_data)
            }
        
        return {
            "statusCode": 405,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Method {method} not allowed. Only GET requests are supported."})
        }
        
    except Exception as e:
        logger.error(f"Lambda handler error: {e}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }
