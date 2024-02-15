from typing import Optional, List
from starlette.background import BackgroundTasks
from fastapi import File
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from fastapi.routing import APIRouter
from apps.users.utils import *

UPLOAD_DIR = 'uploads'
# 创建一个API路由器实例
user_router = APIRouter()


# 令牌响应模型，包含访问令牌及其类型
class Token(BaseModel):
    token: str
    token_type: str


# 用于提取令牌数据的模型，如用户名
class TokenData(BaseModel):
    username: Union[str, None] = None


# 用户注册信息的模型，包含用户名、密码、邮箱等字段
class UserRegister(BaseModel):  # 注册模型字段
    username: str
    password: str
    email: Union[str, None] = None  # 可选字段
    nick_name: str
    avatar: Optional[str] = None
    create_time: datetime


class UserInfo(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    nick_name: Optional[str] = None
    avatar: Optional[str] = None
    create_time: Optional[datetime] = None
    role: int = 1  # 0为管理者 1为员工
    disabled: bool = False  # 控制账户是否被禁用
    phone_num: Optional[int] = None


class UpdateUser(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    nick_name: Optional[str] = None
    avatar: Optional[str] = None
    create_time: Optional[datetime] = None
    role: int = 1  # 0为管理者 1为员工
    disabled: bool = False  # 控制账户是否被禁用
    phone_num: Optional[int] = None


class UserAvatar(BaseModel):
    avatar: str


# 用户登录接口，验证用户名和密码，返回访问令牌
@user_router.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"token": access_token, "token_type": "bearer"}


# 用户注册接口，注册新用户并返回访问令牌
@user_router.post("/register", response_model=Token)
async def register_user(user_data: UserRegister):
    # 检查用户名是否已存在
    existing_user = await User.get_or_none(username=user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # 散列用户密码
    hashed_password = pwd_context.hash(user_data.password)

    # 创建新用户并保存到数据库
    user = User(username=user_data.username, password_hash=hashed_password, email=user_data.email)
    await user.save()

    # 为新用户创建访问令牌
    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": user.username}, expires_delta=token_expires
    )

    # 返回新创建的访问令牌
    return {"token": token, "token_type": "bearer"}


# 获取用户信息
@user_router.get("/me", response_model=UserInfo)
async def read_user_me(current_user: User = Depends(get_current_user)):
    """
    获取当前认证用户的信息
    """
    if current_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return current_user


# 获取所有用户信息
@user_router.get("/all", response_model=List[UserInfo])
async def read_user_all(current_user: User = Depends(get_current_user)):
    # 确保current_user存在
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    # 直接使用Pydantic模型进行异步查询，而不是先查询字典再进行转换
    users = await User.all().values("id", "username", "nick_name", "avatar", "role", "phone_num", "create_time", "email", "disabled")
    return [UserInfo(**user) for user in users]


# 修改用户信息
@user_router.put("/me/{user_id}", response_model=UpdateUser)
async def update_user(user_id: int, user_update: UpdateUser, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user's information")
    # 将Pydantic模型转换为字典，排除任何默认值以确保只更新用户提供的字段
    update_data = user_update.model_dump(exclude_unset=True)
    # 检查是否有要更新的数据
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided to update")

    # 使用Tortoise ORM的.filter()和.update()方法来更新数据库中的用户记录
    updated_count = await User.filter(id=user_id).update(**update_data)

    # 检查是否成功更新了记录
    if not updated_count:
        raise HTTPException(status_code=404, detail=f"User with id {user_id} not found")

    # 重新获取并返回更新后的用户信息
    updated_user = await User.get(id=user_id)
    return updated_user


# 定义上传头像接口
@user_router.post("/upload/avatar", response_model=UserAvatar)
async def create_upload_avatar(background_tasks: BackgroundTasks, file: UploadFile = File(...),
                               current_user: User = Depends(get_current_active_user)):
    if not file.filename.endswith(('.png', '.jpg', '.jpeg', 'gif')):
        raise HTTPException(status_code=400, detail="Invalid file format")

    # 使用后台任务来处理文件保存和数据库更新，以免阻塞请求
    avatar_path = await handle_upload_file(file, current_user.username)
    avatar_url = await get_user_avatar_url(avatar_path)  # 获取用户头像的完整URL

    # 返回更新后的头像URL
    return {"avatar": avatar_url}


@user_router.post("/logout")
async def logout(token: str = Depends(validate_token)):
    # 将令牌添加到黑名单中
    token_blacklist.append(token)
    return {"message": "User logged out successfully"}
