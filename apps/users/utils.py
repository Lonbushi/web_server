# 从数据库获取用户信息的异步函数
from typing import Union
import aiofiles
from fastapi import Depends, HTTPException, UploadFile
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from starlette import status
from tortoise.exceptions import DoesNotExist
from apps.users.models import User
from datetime import datetime, timedelta, timezone

# 定义JWT令牌的密钥、加密算法和令牌过期时间
SECRET_KEY = "d08b2ef4424a54dce2de09c5c69a513dfcf06284ccba47c3d8701d3e51d2b32a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# 定义一个jwt黑名单
token_blacklist = []

# 密码加密上下文配置，使用bcrypt算法
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2的密码流令牌获取URL配置
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_user(username: str):
    return await User.get(username=username)


# 验证明文密码和散列密码是否匹配
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# 验证用户身份的异步函数
async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user.password_hash):
        return False
    return user


# 创建访问令牌的函数，可以设置令牌的过期时间
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# 获取当前用户的异步函数，从令牌中提取用户信息
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"}, )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = await get_user(username)
        if user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user


# 获取当前活跃用户的异步函数，检查用户是否被禁用
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# 假设我们有一个函数用于保存上传的文件到磁盘
async def save_upload_file(upload_file: UploadFile, destination: str):
    """
    异步保存上传的文件到指定路径。
    """
    async with aiofiles.open(destination, 'wb') as out_file:
        # 读取上传文件的内容
        content = await upload_file.read()
        # 写入到目标文件
        await out_file.write(content)
        # 重置文件游标
        await upload_file.seek(0)


async def update_user_avatar(username: str, avatar_path: str):
    """
    使用Tortoise-ORM异步更新用户头像路径。
    """
    try:
        # 查找指定的用户
        user = await User.get(username=username)
        # 更新用户的头像路径
        user.avatar = avatar_path
        # 保存更改到数据库
        await user.save()
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")


async def handle_upload_file(upload_file: UploadFile, username: str):
    file_location = f"uploads/{username}_{upload_file.filename}"
    await save_upload_file(upload_file, file_location)
    # 保存完文件后，立即更新用户头像路径
    await update_user_avatar(username, file_location)
    return file_location


# 假设 get_user_avatar_url 是一个函数，用于根据文件位置生成可访问的URL
async def get_user_avatar_url(file_location: str) -> str:
    # 这里应该根据实际情况来生成可访问的URL，例如通过静态文件服务或CDN
    return f"http://127.0.0.1:8080/{file_location}"


# 验证是否需要在黑名单中
def validate_token(token: str = Depends(oauth2_scheme)):
    if token in token_blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is revoked"
        )
    return token
