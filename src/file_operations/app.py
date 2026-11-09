import json
import boto3
import base64
from botocore.exceptions import ClientError

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,GET,POST,DELETE",
    "Access-Control-Allow-Headers": "Content-Type"
}

BUCKET_NAME = "docshield-storage"
s3 = boto3.client("s3")

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
        
        # Get file key from path parameters or query parameters (only for GET and DELETE)
        path_params = event.get("pathParameters", {}) or {}
        query_params = event.get("queryStringParameters", {}) or {}
        
        if method == "GET" or method == "DELETE":
            file_key = path_params.get("fileKey") or query_params.get("fileKey")
            if not file_key:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing fileKey parameter"})
                }
            
            # Validate user access (ensure user can only access their own files)
            user_email = query_params.get("userEmail")
            if user_email and not file_key.startswith(f"{user_email}/"):
                return {
                    "statusCode": 403,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Access denied. You can only access your own files."})
                }
        
        if method == "GET":
            return handle_view_download(file_key, query_params)
        elif method == "DELETE":
            user_email = query_params.get("userEmail")
            return handle_delete(file_key, user_email)
        elif method == "POST":
            # For POST operations, also check for user_email in the request body
            try:
                body = json.loads(event.get("body", "{}"))
                body_user_email = body.get("userEmail")
                query_user_email = query_params.get("userEmail")
                effective_user_email = query_user_email or body_user_email
            except:
                effective_user_email = query_params.get("userEmail")
            return handle_post_operations(event, effective_user_email)
        else:
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

def handle_post_operations(event, user_email):
    """Handle POST operations like batch delete and document viewing"""
    try:
        body = json.loads(event.get("body", "{}"))
        operation = body.get("operation")
        doc_id = body.get("docId")
        
        # Handle document viewing via POST (for your frontend)
        if doc_id and not operation:
            return handle_view_document_by_id(doc_id, user_email)
        elif operation == "presigned_url" and doc_id:
            action = body.get("action", "view")  # Default to view, can be "download"
            return handle_generate_presigned_url(doc_id, user_email, action)
        
        if operation == "delete":
            # Handle single file deletion via POST
            file_key = body.get("fileKey") or body.get("docId")
            if not file_key:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Missing fileKey or docId parameter"})
                }
            
            # If user_email is provided and fileKey doesn't contain user prefix, add it
            if user_email and not file_key.startswith(f"{user_email}/"):
                file_key = f"{user_email}/{file_key}"
            
            return handle_delete(file_key, user_email)
            
        elif operation == "batch_delete":
            file_keys = body.get("fileKeys", [])
            if not file_keys:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "No file keys provided for batch delete"})
                }
            return handle_batch_delete(file_keys, user_email)
        else:
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Invalid operation. Supported operations: delete, batch_delete, presigned_url, or provide docId for document viewing"})
            }
            
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Invalid JSON in request body"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }

def handle_view_download(file_key, query_params):
    """Handle viewing file metadata or downloading file content"""
    try:
        action = query_params.get("action", "view")  # 'view' for metadata, 'download' for content
        
        # Handle list user files action
        if action == "list":
            user_email = query_params.get("userEmail")
            if not user_email:
                return {
                    "statusCode": 400,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "userEmail parameter required for listing files"})
                }
            return handle_list_user_files(user_email)
        
        if action == "view":
            # Get file metadata
            response = s3.head_object(Bucket=BUCKET_NAME, Key=file_key)
            
            metadata = {
                "key": file_key,
                "filename": file_key.split("/")[-1],
                "size": response.get("ContentLength", 0),
                "lastModified": response.get("LastModified").isoformat() if response.get("LastModified") else None,
                "contentType": response.get("ContentType", "application/octet-stream"),
                "metadata": response.get("Metadata", {}),
                "etag": response.get("ETag", "").strip('"')
            }
            
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"file": metadata})
            }
            
        elif action == "download":
            # Download file content
            response = s3.get_object(Bucket=BUCKET_NAME, Key=file_key)
            file_content = response["Body"].read()
            
            # Encode content as base64 for JSON response
            encoded_content = base64.b64encode(file_content).decode("utf-8")
            
            return {
                "statusCode": 200,
                "headers": {
                    **CORS_HEADERS,
                    "Content-Disposition": f'attachment; filename="{file_key.split("/")[-1]}"'
                },
                "body": json.dumps({
                    "filename": file_key.split("/")[-1],
                    "contentType": response.get("ContentType", "application/octet-stream"),
                    "content": encoded_content,
                    "size": len(file_content)
                }),
                "isBase64Encoded": False
            }
            
        elif action == "presigned":
            # Generate presigned URL for direct download
            try:
                presigned_url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': BUCKET_NAME, 'Key': file_key},
                    ExpiresIn=3600  # URL expires in 1 hour
                )
                
                return {
                    "statusCode": 200,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "downloadUrl": presigned_url,
                        "filename": file_key.split("/")[-1],
                        "expiresIn": 3600
                    })
                }
            except ClientError as e:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": f"Failed to generate presigned URL: {str(e)}"})
                }
        
        else:
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Invalid action. Use 'view', 'download', 'presigned', or 'list'"})
            }
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchKey':
            return {
                "statusCode": 404,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "File not found"})
            }
        else:
            return {
                "statusCode": 500,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": f"AWS Error: {str(e)}"})
            }

def handle_delete(file_key, user_email):
    """Handle deleting a file from S3"""
    try:
        # Additional security check
        if user_email and not file_key.startswith(f"{user_email}/"):
            return {
                "statusCode": 403,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Access denied. You can only delete your own files."})
            }
        
        # Check if file exists before deleting
        try:
            s3.head_object(Bucket=BUCKET_NAME, Key=file_key)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "File not found"})
                }
            raise e
        
        # Delete the file
        s3.delete_object(Bucket=BUCKET_NAME, Key=file_key)
        
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "File deleted successfully",
                "deletedFile": file_key
            })
        }
        
    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Failed to delete file: {str(e)}"})
        }

def handle_list_user_files(user_email):
    """List all files for a specific user"""
    try:
        prefix = f"{user_email}/"
        
        response = s3.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=prefix
        )
        
        files = []
        if 'Contents' in response:
            for obj in response['Contents']:
                # Skip folder markers (keys ending with /)
                if not obj['Key'].endswith('/'):
                    files.append({
                        "key": obj['Key'],
                        "filename": obj['Key'].split('/')[-1],
                        "size": obj['Size'],
                        "lastModified": obj['LastModified'].isoformat(),
                        "etag": obj['ETag'].strip('"')
                    })
        
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "userEmail": user_email,
                "totalFiles": len(files),
                "files": files
            })
        }
        
    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Failed to list files: {str(e)}"})
        }

def handle_batch_delete(file_keys, user_email):
    """Handle deleting multiple files from S3 (bonus functionality)"""
    try:
        # Validate all files belong to the user
        if user_email:
            for key in file_keys:
                if not key.startswith(f"{user_email}/"):
                    return {
                        "statusCode": 403,
                        "headers": CORS_HEADERS,
                        "body": json.dumps({"error": f"Access denied for file: {key}"})
                    }
        
        # Prepare objects for batch deletion
        objects_to_delete = [{"Key": key} for key in file_keys]
        
        # Batch delete
        response = s3.delete_objects(
            Bucket=BUCKET_NAME,
            Delete={
                "Objects": objects_to_delete,
                "Quiet": False
            }
        )
        
        deleted_files = [obj.get("Key") for obj in response.get("Deleted", [])]
        errors = response.get("Errors", [])
        
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "Batch delete completed",
                "deletedFiles": deleted_files,
                "errors": errors,
                "totalDeleted": len(deleted_files)
            })
        }
        
    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Failed to delete files: {str(e)}"})
        }

def handle_view_document_by_id(doc_id, user_email):
    """Handle document viewing by document ID (for frontend POST requests)"""
    try:
        # If user_email is provided, construct the file key with user prefix
        if user_email:
            file_key = f"{user_email}/{doc_id}"
        else:
            # If no user email, assume doc_id is the full file key
            file_key = doc_id
        
        # Validate user access
        if user_email and not file_key.startswith(f"{user_email}/"):
            return {
                "statusCode": 403,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Access denied. You can only access your own files."})
            }
        
        # Get the file from S3
        response = s3.get_object(Bucket=BUCKET_NAME, Key=file_key)
        file_content = response["Body"].read()
        content_type = response.get("ContentType", "application/octet-stream")
        filename = file_key.split("/")[-1]
        
        # Determine proper content type based on file extension if not set correctly
        if content_type == "application/octet-stream" or content_type == "binary/octet-stream":
            if filename.lower().endswith('.pdf'):
                content_type = "application/pdf"
            elif filename.lower().endswith(('.doc', '.docx')):
                content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if filename.lower().endswith('.docx') else "application/msword"
            elif filename.lower().endswith('.txt'):
                content_type = "text/plain"
        
        # Return the file as binary data for direct viewing/download
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": content_type,
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "OPTIONS,GET,POST,DELETE",
                "Access-Control-Allow-Headers": "Content-Type,Authorization",
                "Access-Control-Expose-Headers": "Content-Disposition,Content-Length",
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(file_content)),
                "Cache-Control": "no-cache"
            },
            "body": base64.b64encode(file_content).decode("utf-8"),
            "isBase64Encoded": True
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchKey':
            return {
                "statusCode": 404,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Document not found"}),
                "isBase64Encoded": False
            }
        else:
            return {
                "statusCode": 500,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": f"AWS Error: {str(e)}"}),
                "isBase64Encoded": False
            }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)}),
            "isBase64Encoded": False
        }

def handle_generate_presigned_url(doc_id, user_email, action="view"):
    """Generate a presigned URL for document viewing or downloading"""
    try:
        # Construct file key
        if user_email:
            file_key = f"{user_email}/{doc_id}"
        else:
            file_key = doc_id
        
        # Validate user access
        if user_email and not file_key.startswith(f"{user_email}/"):
            return {
                "statusCode": 403,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Access denied. You can only access your own files."})
            }
        
        # Check if file exists
        try:
            s3.head_object(Bucket=BUCKET_NAME, Key=file_key)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return {
                    "statusCode": 404,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"error": "Document not found"})
                }
            raise e
        
        # Determine content disposition based on action
        filename = file_key.split("/")[-1]
        if action == "download":
            content_disposition = f'attachment; filename="{filename}"'
        else:  # view (default)
            content_disposition = 'inline'
        
        # Determine the correct content type based on file extension
        file_extension = filename.lower().split('.')[-1] if '.' in filename else ''
        content_type_mapping = {
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt': 'text/plain',
            'html': 'text/html',
            'htm': 'text/html',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif'
        }
        response_content_type = content_type_mapping.get(file_extension, 'application/octet-stream')
        
        # Generate presigned URL with appropriate content disposition and content type
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BUCKET_NAME, 
                'Key': file_key,
                'ResponseContentDisposition': content_disposition,
                'ResponseContentType': response_content_type
            },
            ExpiresIn=3600  # URL expires in 1 hour
        )
        
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "downloadUrl": presigned_url,
                "filename": file_key.split("/")[-1],
                "expiresIn": 3600
            })
        }
        
    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Failed to generate presigned URL: {str(e)}"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }