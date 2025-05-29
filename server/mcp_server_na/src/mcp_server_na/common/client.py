import json
from volcengine.auth.SignerV4 import SignerV4
from volcengine.util.Util import *
from volcengine.Credentials import Credentials
from volcengine.base.Service import Service
from volcengine.ApiInfo import ApiInfo
from volcengine.ServiceInfo import ServiceInfo

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    import configparser as configparser
except ImportError:
    import ConfigParser as configparser

DESCRIBE_DIAGNOSIS = "/DescribeDiagnosisInstanceDetail"

API_INFO = {
    DESCRIBE_DIAGNOSIS : ApiInfo("POST", DESCRIBE_DIAGNOSIS, {}, {}, {})
}

class NAService(Service):

    def __init__(self, endpoint: str, access_key_id: str, access_key_secret: str, region: str,
                 security_token: str = None, schema: str="https", timeout: int = 60):
        self.__endpoint = endpoint
        self.__access_key_id = access_key_id
        self.__access_key_secret = access_key_secret
        self.__region = region
        self.__security_token = security_token
        self.__schema = schema
        self.__timeout = timeout
        super(NAService, self).__init__(service_info=self.get_service_info(), api_info=API_INFO)

    def get_region(self):
        return self.__region

    def get_service_info(self):
        header = {}
        credentials = Credentials(ak=self.__access_key_id, sk=self.__access_key_secret,
                                  service="vpc", region=self.__region)
        service_info = ServiceInfo(host=self.__endpoint, header=header, credentials=credentials,scheme=self.__schema,
                                   connection_timeout=self.__timeout, socket_timeout=self.__timeout)
        return service_info

    def __prepare_request(self, api: str, params: dict = None, body: dict = None, request_headers: dict = None):
        if params is None:
            params = {}
        if body is None:
            body = {}

        request = self.prepare_request(self.api_info[api], params)

        if request_headers is None:
            request_headers = {"Content-Type": "application/json"}
        request.headers.update(request_headers)

        if "json" in request.headers["Content-Type"] and api != "/WebTracks":
            request.body = json.dumps(body)
        else:
            request.body = body["Data"]

        if len(request.body) != 0:
            if isinstance(request.body, str):
                request.headers["Content-MD5"] = hashlib.md5(request.body.encode("utf-8")).hexdigest()
            else:
                request.headers["Content-MD5"] = hashlib.md5(request.body).hexdigest()

        SignerV4.sign(request, self.service_info.credentials)

        return request

    def __request(self, api: str, params: dict=None, body: dict=None, request_headers: dict=None):
        request = self.__prepare_request(api, params, body, request_headers)
        method = self.api_info[api].method
        url = request.build()
        response = self.session.request(method, url, headers=request.headers, data=request.body)
        return response

    def describe_diagnose(self):
        api = "/DescribeDiagnosisInstanceDetail"
        params = {
            "Action": "DescribeDiagnosisInstanceDetail",
            "region": "cn-shanghai",
            "DiagnosisInstanceId": "di-3og9u1gq2terk68hqmb6p3eo",
            "Version": "2020-04-01"
        }
        print(self.__request(api, params).content)

if __name__ == '__main__':
    print("hello world")
    k = ""
    s = ""

    na = NAService(endpoint="vpc.cn-beijing.volcengineapi.com", access_key_id=k, access_key_secret=s,
                   schema="https", region="cn-shanghai", security_token="", timeout=10)
    na.describe_diagnose()
    print("====end====")