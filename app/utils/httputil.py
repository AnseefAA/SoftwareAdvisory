"""
HTTP utility functions for making async requests
"""
import logging
from typing import Dict, Optional
import httpx

async def get(url: str, query_params: dict = None, headers: dict = None, timeout: int = 10) -> Dict:
    """
    Send an asynchronous GET request.

    Args:
        url (str): The URL to send the GET request to.
        query_params (dict, optional): Query parameters for the GET request.
        headers (dict, optional): Headers to include in the GET request.
        timeout (int, optional): Timeout for the request in seconds. Defaults to 10.

    Returns:
        dict: The JSON response from the server.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(url, params=query_params, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as e:
        raise RuntimeError(f"An error occurred while making a GET request: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"HTTP error: {e.response.status_code}, {e.response.text}")

async def post(url: str, payload: dict = None, headers: dict = None, timeout: int = 10) -> Dict:
    """
    Send an asynchronous POST request.

    Args:
        url (str): The URL to send the POST request to.
        payload (dict, optional): The payload for the POST request.
        headers (dict, optional): Headers to include in the POST request.
        timeout (int, optional): Timeout for the request in seconds. Defaults to 10.

    Returns:
        dict: The JSON response from the server.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as e:
        raise RuntimeError(f"An error occurred while making a POST request: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"HTTP error: {e.response.status_code}, {e.response.text}")
    except Exception as e:
        logging.debug(f"An error occurred while making a POST request: {str(e)}")
        raise

async def get_html(url: str, headers: dict = None, timeout: int = 10) -> str:
    """
    Send an asynchronous GET request and return HTML content.

    Args:
        url (str): The URL to send the GET request to.
        headers (dict, optional): Headers to include in the GET request.
        timeout (int, optional): Timeout for the request in seconds. Defaults to 10.

    Returns:
        str: The HTML response from the server.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.text
    except httpx.RequestError as e:
        raise RuntimeError(f"An error occurred while making a GET request: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"HTTP error: {e.response.status_code}, {e.response.text}")

# Made with Bob
