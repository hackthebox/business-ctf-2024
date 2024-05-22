from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from routes.api import router as api_router
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from config import Config

app = FastAPI(title="main app", docs_url=None, redoc_url=None)
api = FastAPI(title="api app", docs_url=None, redoc_url=None)

api.include_router(api_router)

app.mount("/api", api)

@app.get('/chat/{room}')
def chat(room: str):
    if not room or room != Config.roomID:
        return RedirectResponse('/', status_code=302)

    return FileResponse('public/chat.html', media_type='html')

app.mount("/", StaticFiles(directory="public", html=True), name="public")

@app.exception_handler(Exception)
async def universal_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred."}
    )