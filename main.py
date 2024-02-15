from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from apps.users.users import user_router
from tortoise.contrib.fastapi import register_tortoise
from setting import TORTOISE_ORM
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://localhost:9528"
]

register_tortoise(
    app=app,
    config=TORTOISE_ORM
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # *：代表所有客户端
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.mount("/static", StaticFiles(directory="statics"))
app.include_router(user_router, prefix="/user", tags=["登录接口"])
# 挂载`uploads`目录，使其文件可以通过`/uploads`路径访问
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

if __name__ == '__main__':
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
