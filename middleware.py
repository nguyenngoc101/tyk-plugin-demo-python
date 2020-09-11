from tyk.decorators import *
from gateway import TykGateway as tyk
from time import time
from google.protobuf.json_format import MessageToDict
import json


@Hook
def PreHook(request, session, spec):
    tyk.log("PreHook is called", "info")
    # Inject a header:
    request.add_header("testheader", "testvalue")
    return request, session

@Hook
def PostHook(request, session, spec):
    tyk.log("PostHook is called", "info")
    return request, session

@Hook
def AuthCheck(request, session, metadata, spec):
    tyk.log("AuthCheck is called", "info")
    return request, session, metadata

@Hook
def PostKeyAuth(request, session, metadata, spec):
    tyk.log("PostKeyAuth is called", "info")
    tyk_request = MessageToDict(request.__dict__['object'])
    req_body = json.loads(tyk_request['body'])
    tyk.log("PostKeyAuth: request body info: {0}".format(req_body), "info")
    tyk.log("PostKeyAuth: req body type: {0}".format(type(req_body)), "info")
    tyk.log("PostKeyAuth: username: {0}".format(req_body['name']), "info")


    # Log the additional metadata (set in AuthCheck):
    username = session.metadata["username"]
    tyk.log("PostKeyAuth: user '{0}' was authenticated".format(username), "info")

    auth_header = request.get_header('Authorization')
    if auth_header == '47a0c79c427728b3df4af62b9228c8ae':
        tyk.log("AuthCheck is successful", "info")
        # Initialize a session object:
        session.rate = 1000.0
        session.per = 1.0
        # Set a deadline for the ID extractor, in this case we use the current UNIX timestamp + 60 seconds:
        session.id_extractor_deadline = int(time()) + 60
        # Attach the token, this is required (used internally by Tyk):
        metadata["token"] = "47a0c79c427728b3df4af62b9228c8ae"

        # Inject additional metadata:
        metadata["username"] = "testuser"
        return request, session, metadata
    tyk.log("AuthCheck failed: invalid token", "error")

    # Set a custom error:
    request.object.return_overrides.response_error = 'Invalid authentication'
    request.object.return_overrides.response_code = 403
    return request, session, metadata

@Hook
def ResponseHook(request, response, session, metadata, spec):
    tyk.log("ResponseHook is called", "info")
    # In this hook we have access to the response object, to inspect it, uncomment the following line:
    # print(response)
    tyk.log("ResponseHook: upstream returned {0}".format(response.status_code), "info")
    return response
