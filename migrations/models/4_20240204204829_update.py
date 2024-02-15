from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE `user` MODIFY COLUMN `create_time` DATETIME(6) NOT NULL  COMMENT '注册时间' DEFAULT CURRENT_TIMESTAMP(6);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE `user` MODIFY COLUMN `create_time` DATE NOT NULL  COMMENT '注册时间';"""
