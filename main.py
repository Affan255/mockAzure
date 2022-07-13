# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import secrets
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler
from google.oauth2 import id_token
from google.auth.transport import requests
app = FastAPI()

logger = logging.getLogger(__name__)
logger.setLevel(10)
logger.addHandler(AzureLogHandler(connection_string='InstrumentationKey=11872f0b-2595-4f0d-9967-f76333dc31e2;IngestionEndpoint=https://eastasia-0.in.applicationinsights.azure.com/;LiveEndpoint=https://eastasia.livediagnostics.monitor.azure.com/'))
# security = HTTPBasic()
CLIENT_ID = '118079434952225645456'
@app.get("/")
def root():
  return {"message": "Hello World"}

@app.post("/webhook/")
async def webhook(request: Request):

  # logger.info(request.headers.get('authorization'))
  token = str(request.headers.get('authorization')).split(' ')[1]

  try:
    idinfo = id_token.verify_oauth2_token(token, requests.Request())
    logger.info(idinfo)
    userid = idinfo['sub']
    # logger.info(userid)

  except:
    logger.error('Invalid Token')

  # correct_username = secrets.compare_digest(credentials.username, "user")
  # correct_password = secrets.compare_digest(credentials.password, "versa123")
  # if not (correct_username and correct_password):
  #   raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
  dict = {
    "fulfillmentMessages": [
      {
        "text": {
          "text": [
            "It must handle HTTPS requests.\nIts URL for requests must be publicly accessible.\nIt must handle POST requests with a JSON WebhookRequest body.\nIt must respond to WebhookRequest requests with a JSON WebhookResponse body."
          ]
        }
      }
    ]
  }

  dict1 = {
    "fulfillmentMessages": [
      {
        "text": {
          "text": [
            "If your webhook service encounters an error, it should return one of the following HTTP status codes:\n400 Bad Request\
401 Unauthorized\n\
403 Forbidden\n\
404 Not found\n\
500 Server fault\n\
503 Service Unavailable"
          ]
        }
      }
    ]
  }

  dict2 = {
    "fulfillmentMessages": [
      {
        "text": {
          "text": [ "To enable and manage fulfillment for your agent with the console:\n\
Go to the Dialogflow ES Console.\n\
Select an agent.\n\
Select Fulfillment in the left sidebar menu.\n\
Toggle the Webhook field to Enabled.\n\
Provide the details for your webhook service in the form. If your webhook doesn't require authentication, leave the authentication fields blank.\n\
Click Save at the bottom of the page."
          ]
        }
      }
    ]
  }
  fallback = {
    "fulfillmentMessages": [
      {
        "text": {
          "text": ["We apologize that we don't have enough information in this regard. Please contact "
                   "support@versa-networks.com for further help."]
        }
      }
    ]
  }

  body = await request.json()
  if "webhook error" in  body['queryResult']['queryText']:
    return dict1
  elif "requirements met by webhook service" in  body['queryResult']['queryText']:
    return dict
  elif "enable and manage webhook fulfilment" in body['queryResult']['queryText']:
    return dict2
  else:
    return fallback