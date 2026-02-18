

from app.utils.httputil import post


async def fetch_concert_access_token() -> str:
    user_name = "ibmconcert"
    password = "password"
    return await get_bearer_token(user_name,password)
    
async def get_bearer_token(user_name,password : str) -> str:
    url = "https://sk1.fyre.ibm.com:12443/core/api/v1/login"
    # url = "http://9.30.96.106:12443/core/api/v1/login"
    headers = {
        "Content-Type": "application/json",
        "InstanceId": "0000-0000-0000-0000"
    }
    payload = {
        "username": user_name,
        "password": password,
    }

    try:
        response = await post(url, payload=payload, headers=headers , timeout = 30)
        token = response.get("token")

        if not token:
            raise ValueError("Access token not found in response")
        return token

    except Exception as e:
        raise RuntimeError(f"Failed to retrieve access token: {e}")
    

    