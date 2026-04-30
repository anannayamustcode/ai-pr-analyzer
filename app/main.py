from fastapi import FastAPI
from app.github.webhook import router

app = FastAPI()

app.include_router(router)

@app.get("/")
def home():
    return {"status": "running"}


# from fastapi import FastAPI, Request
# from dotenv import load_dotenv
# from app.github.webhook import router
# app = FastAPI()
# app.include_router(router)
# import os

# # 🔹 THIS PART loads your .env file
# load_dotenv()

# print("App ID from .env:", os.getenv("GITHUB_APP_ID"))

# app = FastAPI()

# @app.get("/")
# def home():
#     return {"status": "running"}

# @app.post("/webhook")
# async def webhook(request: Request):
#     payload = await request.json()
#     print("Webhook received:", payload.get("action"))
#     return {"ok": True}