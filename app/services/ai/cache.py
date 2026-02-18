import os
import json
from typing import Optional, Any, Callable
from app.utils.fileutil import get_absolute_path, read_file, write_file

class FileSystemCache:
    def __init__(
        self,
        cve_id: str,
        filename: str,
        subdir: Optional[str] = None,
        parser: Optional[Callable[[str], Any]] = json.loads
    ) -> None:
        """
        Initializes a FileSystemCache instance.

        :param cve_id: Identifier for the cache entry.
        :param filename: Name of the file associated with the cache.
        :param subdir: Optional subdirectory path within the cache directory.
        :param parser: Function to parse the file contents (default: `json.loads`).
        """
        self.cve_id = cve_id
        self.filename = filename
        self.subdir = subdir

        base_path = os.path.splitext(os.path.basename(self.filename))[0]
        self.abs_path = get_absolute_path(f"app/data/{base_path}/{subdir}" if subdir else f"app/data/{base_path}")
        self.prompt_path = os.path.join(self.abs_path, f"{self.cve_id}-prompt.txt")
        self.response_path = os.path.join(self.abs_path, f"{self.cve_id}-response.txt")
        self.parser = parser

    def lookup(self) -> Optional[Any]:
        """
        Reads and parses the cached response file.

        :return: Parsed content of the response file, or None if the file does not exist.
        """
        try:
            return read_file(self.response_path, self.parser)
        except Exception:
            return None

    def update(self, prompt: str, llm_response: Any) -> None:
        """
        Updates the cache with new prompt and response data.

        :param prompt: The prompt text to be written to the prompt file.
        :param response: The response data to be written to the response file.
        """
        try:
            write_file(self.prompt_path, prompt)
            write_file(self.response_path, llm_response)
        except Exception as e   :
            print(e)
            
    def update_response_file(self, llm_response: Any) -> None:
        """
        Updates the cache with  response data.

        :param response: The response data to be written to the response file.
        """
        try:
            write_file(self.response_path, llm_response)
        except Exception as e   :
            print(e)
