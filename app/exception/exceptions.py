from fastapi import HTTPException


def permission_denied_error():
    return HTTPException(
        status_code=422,
        detail=[
            {
                "loc": ["body", "file_permissions"],
                "msg": "Permission denied to write the file.",
                "type": "file_error.permission_denied"
            }
        ]
    )

def invalid_filename_error():
    return HTTPException(
        status_code=422,
        detail=[
            {
                "loc": ["body", "filename"],
                "msg": "Failed to generate a valid filename.",
                "type": "file_error.invalid_filename"
            }
        ]
    )

def general_file_error(message: str):
    return HTTPException(
        status_code=500,
        detail=[
            {
                "loc": ["body", "file_upload"],
                "msg": message,
                "type": "file_error.general"
            }
        ]
    )

def invalid_data_error():
    return HTTPException(
        status_code=422,
        detail=[
            {
                "loc": ["body", "data_format"],
                "msg": "Invalid data format in the file.",
                "type": "file_error.invalid_data"
            }
        ]
    )

    
def file_not_found_error(filename: str):
    return HTTPException(
        status_code=404,
        detail=[
            {
                "loc": ["query", "filename"],
                "msg": f"File '{filename}' not found.",
                "type": "file_error.not_found"
            }
        ]
    )
    
def not_found_error():
    return HTTPException(
        status_code=404,
        detail=[
            {
                "loc": ["query",],
                "msg": f"404 Not Found",
                "type": "not_found"
            }
        ]
    )
    
def general_error():
    return HTTPException(
        status_code=422,
        detail=[
            {
                "loc": ["query", "filename"],
                "msg": "API Fail.",
                "type": ""
            }
        ]
    )
    
    
