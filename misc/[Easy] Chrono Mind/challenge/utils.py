from config import Config
import os, uuid, subprocess

def readFile(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except:
        return None

def getRepository(topic):
    for suffix in ['', '.md']:
        repoFile = f"{Config.knowledgePath}/{topic}{suffix}"
        print(repoFile)
        if os.path.exists(repoFile):
            return readFile(repoFile)
    return None

def evalCode(code):
    output = ""
    random = uuid.uuid4().hex
    filename = os.path.join("uploads/") + random + ".py"
    try:
        with open(filename, "w") as f:
            f.write(code)

        output = subprocess.run(
            ["python3", filename],
            timeout=10,
            capture_output=True,
            text=True,
        ).stdout.strip("\n")

        cleanup(filename)

        return output

    except Exception as e: # handle any exception
        print(e, flush=True)
        cleanup(filename)
        return False


def cleanup(filename):
    try:
        os.remove(filename)
    except:
        pass