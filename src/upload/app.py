import boto3
import json
import base64
import uuid
from datetime import datetime

# Initialize S3 client
s3 = boto3.client("s3")
BUCKET_NAME = "docshield-storage"

# Common CORS headers
CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": "Content-Type"
}

def add_tags_to_s3_object(bucket, key, tags_dict):
    """
    Add tags to an S3 object using put_object_tagging
    tags_dict: Dictionary of tag key-value pairs
    """
    try:
        tag_set = [{"Key": k, "Value": v} for k, v in tags_dict.items()]
        s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={"TagSet": tag_set}
        )
        return True
    except Exception as e:
        print(f"Error adding tags: {str(e)}")
        return False

def lambda_handler(event, context):
    try:
        method = event.get("httpMethod", "")

        # Handle CORS preflight
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CORS preflight OK"})
            }

        if method == "POST":
            # Parse request body
            body = event.get("body", "")
            is_base64 = event.get("isBase64Encoded", False)
            if not body:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "No file data provided"})
                }

            # Parse metadata from queryStringParameters or headers
            params = event.get("queryStringParameters", {}) or {}

            title = params.get("title", "untitled")
            doc_type = params.get("type", "Others")
            userEmail = params.get("userEmail", "unknown")  # Get userEmail from params, default to 'unknown'
            # You can also parse from headers if you prefer

            # Try to get filename and extension from body (for frontend compatibility)
            original_filename = None
            try:
                body_json = json.loads(body) if not is_base64 else None
                if body_json:
                    original_filename = body_json.get("filename")
                    # Overwrite title/type/userEmail if sent in body
                    title = body_json.get("title", title)
                    doc_type = body_json.get("type", doc_type)
                    userEmail = body_json.get("userEmail", userEmail)
                    # Get file content from body
                    file_content = base64.b64decode(body_json["file"]) if "file" in body_json else None
                else:
                    file_content = base64.b64decode(body) if is_base64 else body.encode("utf-8")
            except Exception:
                file_content = base64.b64decode(body) if is_base64 else body.encode("utf-8")

            # Determine file extension
            if original_filename and "." in original_filename:
                ext = original_filename.split(".")[-1]
                safe_ext = ext if len(ext) <= 10 else "bin"
            else:
                safe_ext = "bin"
            # Generate a unique filename with original extension
            filename = f"{uuid.uuid4()}_{title.replace(' ', '_')}.{safe_ext}"
            # Check if the folder (prefix) exists in S3
            prefix = f"{userEmail}/"
            response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix, MaxKeys=1)
            # S3 will create the folder if it doesn't exist, so just upload
            s3_key = f"{userEmail}/{filename}"
            # Upload the file first
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=s3_key,
                Body=file_content,
                Metadata={
                    "title": title,
                    "type": doc_type,
                    "userEmail": userEmail
                }
            )
            
            # Add tags to the uploaded object
            upload_tags = {
                "verification_status": "Pending Verification",
                "document_type": doc_type,
                "uploaded_by": userEmail,
                "upload_date": datetime.now().isoformat(),
                "original_filename": original_filename or filename
            }
            
            # Add tags using the helper function
            add_tags_to_s3_object(BUCKET_NAME, s3_key, upload_tags)
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "File uploaded successfully!", "filename": s3_key})
            }

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