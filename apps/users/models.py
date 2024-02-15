from tortoise.models import Model
from tortoise import fields


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=32, description="用户名")
    password_hash = fields.CharField(max_length=60, description="密码")
    email = fields.CharField(max_length=255, null=True)  # 添加 email 字段
    avatar = fields.CharField(max_length=255, description="头像", null=True)
    nick_name = fields.CharField(max_length=255, default="昵称")
    phone_num = fields.CharField(max_length=16, description="手机号", null=True)
    create_time = fields.DatetimeField(auto_now_add=True, description="注册时间")
    role = fields.IntField(description="权限管理", default=1)  # 0为管理者 1为员工
    disabled = fields.BooleanField(default=False)  # 控制账户是否被禁用
