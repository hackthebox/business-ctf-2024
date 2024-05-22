import os

class Config():
    roomID = None
    createProgress = False
    chatProgress = False
    knowledgePath = f"{os.getcwd()}/repository"
    copilot_key = "REDACTED_SECRET"