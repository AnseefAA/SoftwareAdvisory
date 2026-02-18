import os
import time
from app.utils.httputil import post_form
import logging

logger = logging.getLogger('WCAAccessTokenManager')

class WCAAccessTokenManager:
    def __init__(self):
        self.access_token = None
        self.access_token_expiration = 0

    async def fetch_new_access_token(self):
        try:
            # Make the API call to fetch the new access token
            access_token_response = await post_form(
                url="https://iam.cloud.ibm.com/identity/token",
                form_data={
                    "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                    "apikey": os.getenv("WCA_API_KEY"),  # Fetch API key from environment variables
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            # Validate and extract the access token
            self.access_token = access_token_response.get("access_token")
            self.access_token_expiration = time.time() + 3600  # Set expiration to 1 hour from now
            logger.info("New WCA access token fetched successfully")

        except Exception as e:
            print("Error while fetching new access token:", str(e))

    async def get_access_token(self):
        # Check if the token is valid or expired
        if self.access_token and time.time() < self.access_token_expiration:
            logger.info("Reusing an existing WCA access token")
            return self.access_token
        else:
            await self.fetch_new_access_token()
            return self.access_token
