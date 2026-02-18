import asyncio
import json
import os
from pathlib import Path

from app.exception import exceptions
from typing import Optional, Any, Callable, Dict
    
def get_absolute_file_path(parent_folder_path , filename : str) -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, f"{parent_folder_path}/{filename}")

def get_filename_without_exstension(filename : str) -> str:
    return os.path.splitext(filename)[0]

def dir_creator(parent_folder_path :str):
    if not os.path.exists(parent_folder_path):
        os.makedirs(parent_folder_path)
        
def check_file_exists(file_path: str) -> bool:
    return Path(file_path).exists()
        
def file_writer_sync(file_path: str, file_data: bytes):
    with open(file_path, "wb+") as buffer:
        buffer.write(file_data)

async def file_writer(file_path: str, file_data: bytes):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None,file_writer_sync, file_path, file_data)
    
def file_loader(file_path_with_extension :str) -> Dict: 
    try:
        with open(file_path_with_extension, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise exceptions.file_not_found_error(file_path_with_extension)
    except json.JSONDecodeError:
        return {}
        # raise exceptions.invalid_json_error(file_path_with_extension)
    except Exception as e:
        raise exceptions.general_file_error(str(e))
    
def get_absolute_path(relative_path: str) -> str:
    """
    Get the absolute path of a given relative path.

    Parameters:
        relative_path (str): The relative path to the file or directory.

    Returns:
        str: The absolute path.
    """
    return os.path.abspath(relative_path) 

def read_file(file_path: str, parser: Optional[Callable[[str], Any]] = None) -> Optional[Any]:
    """
    Reads and optionally parses the content of a file.

    Args:
        file_path (str): The path to the file.
        parser (Callable, optional): A function to parse the content after reading. Defaults to None.

    Returns:
        Optional[Any]: The file content, either raw or parsed. Returns None if an error occurs.
    """
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        if parser:
            return parser(content)
        return content

    except FileNotFoundError as e:
        raise e
    except Exception as e:
        raise e

def write_file(file_path: str, content: str, mode: str = 'w') -> None:
    """
    Writes content to a file, ensuring parent directories exist.

    Args:
        file_path (str): Path to the file.
        content (str): Content to write.
        mode (str): Mode to open the file ('w' for overwrite, 'a' for append). Defaults to 'w'.

    Returns:
        None
    """
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Write content to the file
        with open(file_path, mode, encoding='utf-8') as file:
            file.write(content)
            if not content.endswith('\n'):
                file.write('\n')  # Append newline if missing
    except Exception as e:
        raise e
    
