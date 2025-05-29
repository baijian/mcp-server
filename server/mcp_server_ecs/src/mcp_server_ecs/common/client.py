import os
import volcenginesdkcore
from volcenginesdkecs.api.ecs_api import ECSApi
from mcp_server_ecs.conf.config import auth_config

_ecs_client = None


def get_volc_ecs_client(configuration=volcenginesdkcore.Configuration()) -> ECSApi:
    global _ecs_client
    if _ecs_client is None:
        ecs_config = configuration

        # 优先从环境变量获取配置，如果没有则使用 auth_config
        ecs_config.ak = os.environ.get(
            "VOLC_ACCESSKEY") or auth_config.get("ak")
        ecs_config.sk = os.environ.get(
            "VOLC_SECRETKEY") or auth_config.get("sk")
        ecs_config.region = os.environ.get(
            "VOLC_REGION") or auth_config.get("region")
        ecs_config.host = os.environ.get(
            "VOLC_ENDPOINT") or auth_config.get("endpoint")

        ecs_config.client_side_validation = True
        volcenginesdkcore.Configuration.set_default(ecs_config)
        _ecs_client = ECSApi()

    return _ecs_client
