import boto3
import os
import json
import hmac
import hashlib
import base64

USER_POOL_ID = os.environ['userPoolID']
CLIENT_ID = os.environ['clientID']
CLIENT_SECRET = os.environ['clientSecret']
client = None


def get_secret_hash(username):
    msg = username + CLIENT_ID
    digest = hmac.new(
        str(CLIENT_SECRET).encode('utf-8'),
        msg=str(msg).encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    dec = base64.b64encode(digest).decode()
    return dec


def initiate_auth(username, password):
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'SECRET_HASH': get_secret_hash(username),
                'PASSWORD': password
            },
            ClientMetadata={
                'username': username,
                'password': password
            })
    except client.exceptions.NotAuthorizedException as e:
        return None, f"The username or password is incorrect\n {e}"
    except client.exceptions.UserNotFoundException as e:
        return None, f"The username or password is incorrect\n {e}"
    except Exception as e:
        print(e)
        return None, "Unknown error"
    return resp, None


def refresh_auth(username, refresh_token):
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token,
                'SECRET_HASH': get_secret_hash(username)
            },
            ClientMetadata={}
        )
    except client.exceptions.NotAuthorizedException:
        return None, "The username or password is incorrect"
    except client.exceptions.UserNotFoundException:
        return None, "The username or password is incorrect"
    except Exception as e:
        print(e)
        return None, "Unknown error"
    return resp, None


def handler(event, context):
    global client
    if client is None:
        client = boto3.client('cognito-idp')

    event_body = json.loads(event['body'])

    if "username" in event_body.keys():
        username = event_body.get("username")

    if 'password' in event_body.keys():
        resp, msg = initiate_auth(username, event_body.get("password"))

    if 'refresh_token' in event_body.keys():
        resp, msg = refresh_auth(username, event_body.get("refresh_token"))

    if msg is not None:
        return {
            'status': 'fail',
            'msg': msg
        }

    response = {
        'status': 'success',
        'id_token': resp['AuthenticationResult']['IdToken']
    }

    if 'password' in event_body.keys():
        response['refresh_token'] = resp['AuthenticationResult']['RefreshToken']

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': f'{json.dumps(response)}'
    }