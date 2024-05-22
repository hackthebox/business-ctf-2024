import languagemodels as lm
from fastapi import APIRouter, Cookie, Response
from pydantic import BaseModel
from uuid import uuid4
from utils import getRepository, evalCode
from config import Config

lm.config['instruct_model'] = 'LaMini-Flan-T5-248M'
lm.config['max_tokens'] = 400

router = APIRouter()

class createParams(BaseModel):
    topic: str

class chatParams(BaseModel):
    prompt: str

class copilotParams(BaseModel):
    code: str
    copilot_key: str

@router.post("/create")
async def createRoom(response: Response, params: createParams):
    # rate limit room creation
    if Config.createProgress == False:
        Config.createProgress = True
    else:
        return {"message": "A room creation is already in progress"}

    # get knowledge repository
    content = getRepository(params.topic)

    if not content:
        Config.createProgress = False
        return {"message": "Failed to fetch this repository, please try again"}


    # clear previous context
    lm.docs.clear()

    # store the doc
    lm.store_doc(content)

    # save params
    Config.roomID = str(uuid4())

    # create session
    response.status_code = 201
    response.set_cookie("room", Config.roomID)

    # room progress is done
    Config.createProgress = False
    return {"room": Config.roomID, "topic": params.topic}

@router.post("/ask")
def ask_gpt(response: Response, chatParams: chatParams, room: str = Cookie(None)):
    if Config.roomID != room:
        response.status_code = 404
        return {"message": "Room does not exist"}

    # get the response
    context = lm.get_doc_context(chatParams.prompt)
    context = context.split("\n")
    context = context[0]

    answer = lm.extract_answer(chatParams.prompt, context)

    # return the response
    return {"answer": answer}

@router.post("/copilot/complete_and_run")
def copilot_complete_and_run(response: Response, params: copilotParams):
    if Config.copilot_key != params.copilot_key:
        response.status_code = 403
        return {"message": "Invalid API key"}

    # get code completion
    completion = lm.code(params.code)

    if not completion.strip():
        return {"message": "Failed to get code completion"}

    full_code = params.code + completion.strip()

    # return the response
    return {"completion": full_code, "result": evalCode(full_code)}