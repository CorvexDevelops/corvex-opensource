# Keys come from the environment or the secrets manager, never from the code.
import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
REGION = "eu-south-1"
PASSWORD_MIN = 12  # minimum length asked of users
