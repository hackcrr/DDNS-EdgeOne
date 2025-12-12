import argparse
import os
import hashlib
import hmac
import threading
import uuid
import time
import json
import logging
import socket
import re
import psutil
import ipaddress
import tempfile
import requests
import yaml
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List

from fastapi import FastAPI, BackgroundTasks, Request, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


# =================== 常量与路径 ===================
HOME_DIR = Path.home()
TEMP_DIR = tempfile.gettempdir()
CURRENT_DIR = Path(__file__).parent
STATIC_PATH = CURRENT_DIR / "static"
STATIC_PATH.mkdir(exist_ok=True)
print(STATIC_PATH)
print(TEMP_DIR)

# =================== FastAPI应用初始化 ===================
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")

# 主页路由
@app.get("/")
async def root():
    """返回主页面"""
    return HTMLResponse(open(STATIC_PATH / "index.html", "r", encoding="utf-8").read())

# 状态API
@app.get("/api/status")
async def get_status():
    """获取服务状态"""
    return {"status": "running", "timestamp": time.time()}

# 日志API
@app.get("/api/logs")
async def get_logs():
    """获取日志信息"""
    return {"logs": []}

# 配置API
@app.get("/api/config")
async def get_config():
    """获取配置信息"""
    config = read_config()
    return {
        "TencentCloud": {
            "SecretId": config.get("secret", {}).get("SecretId", ""),
            "SecretKey": config.get("secret", {}).get("SecretKey", "")
        },
        "EdgeOneZoneId": config.get("zoneId", []),
        "DnsPodRecord": config.get("dnsPodRecord", []),
        "DingTalkWebhook": config.get("dingTalkWebhook", ""),
        "IntervalMin": config.get("intervalMin", 5),
        "SelectIface": config.get("selectIface", ""),
        "IPv6Regex": config.get("ipv6Regex", ""),
        "CustomIPList": config.get("customIPList", [])
    }

@app.post("/api/config")
async def save_config(request: Request):
    """保存配置信息"""
    try:
        data = await request.json()
        
        # 转换配置格式
        config = {
            "secret": {
                "SecretId": data.get("TencentCloud", {}).get("SecretId", ""),
                "SecretKey": data.get("TencentCloud", {}).get("SecretKey", "")
            },
            "zoneId": data.get("EdgeOneZoneId", []),
            "dnsPodRecord": data.get("DnsPodRecord", []),
            "dingTalkWebhook": data.get("DingTalkWebhook", ""),
            "intervalMin": data.get("IntervalMin", 5),
            "selectIface": data.get("SelectIface", ""),
            "ipv6Regex": data.get("IPv6Regex", ""),
            "customIPList": data.get("CustomIPList", [])
        }
        
        # 保存配置
        if write_config(config):
            logger.info("配置保存成功")
            return {"success": True, "msg": "配置已保存"}
        else:
            return {"success": False, "msg": "配置保存失败"}
            
    except Exception as e:
        logger.error(f"保存配置时发生异常: {str(e)}", exc_info=True)
        return {"success": False, "msg": f"保存失败: {str(e)}"}

# 获取加速域名列表
@app.get("/api/accel-domains")
async def get_accel_domains(zone_id: str = Query(None, description="区域ID")):
    """获取加速域名列表"""
    try:
        # 读取配置
        config = read_config()
        secret = config.get("secret", {})
        if not secret:
            return {"success": False, "message": "未配置腾讯云密钥"}
        
        # 如果没有提供zone_id，尝试从配置中获取
        if not zone_id:
            zone_id = config.get("zoneId")
            if not zone_id:
                return {"success": False, "message": "未提供ZoneId且配置中未设置"}
        
        # 确保zone_id是字符串类型
        if isinstance(zone_id, list):
            if zone_id:
                zone_id = zone_id[0]  # 取列表第一个元素
            else:
                return {"success": False, "message": "ZoneId列表为空"}
        
        # 创建客户端并调用查询接口
        client = QcloudClient(secret)
        domains, error = client.describe_acceleration_domains(str(zone_id))
        
        if error:
            return {"success": False, "message": error}
        
        # 返回成功响应
        return {"success": True, "domains": domains}
    except Exception as e:
        logger.error(f"获取加速域名列表时发生异常: {str(e)}", exc_info=True)
        return {"success": False, "message": str(e)}

# 获取网络接口
@app.get("/api/iface")
async def get_network_interfaces():
    """获取网络接口列表"""
    try:
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    except Exception as e:
        logger.error(f"获取网络接口失败: {str(e)}")
        return []

# 获取IPv6地址
@app.get("/api/ipv6-addresses")
async def get_ipv6_addresses(iface: str = Query(...), regex: str = Query("")):
    """获取指定网络接口的IPv6地址"""
    try:
        addresses = []
        if_info = psutil.net_if_addrs().get(iface, [])
        for addr in if_info:
            if addr.family == socket.AF_INET6:
                # 过滤掉本地链路地址(fe80开头)和回环地址(::1)
                if not addr.address.startswith('fe80') and addr.address != '::1':
                    # 应用正则表达式过滤
                    if not regex or re.match(regex, addr.address):
                        addresses.append(addr.address)
        return addresses
    except Exception as e:
        logger.error(f"获取IPv6地址失败: {str(e)}")
        return []

# 获取源站组列表
@app.get("/api/origin-groups/{zone_id}")
async def get_origin_groups(zone_id: str):
    """获取指定ZoneID的所有源站组"""
    try:
        # 读取配置
        config = read_config()
        secret = config.get("secret", {})
        if not secret:
            return {"success": False, "message": "未配置腾讯云密钥"}
        
        # 确保zone_id是字符串类型
        zone_id = str(zone_id)
        
        # 创建客户端并调用查询接口
        client = QcloudClient(secret)
        response = client.describe_all_origin_groups(zone_id)
        
        # 处理响应
        if "Error" in response:
            error_msg = response["Error"].get("Message", "获取源站组列表失败")
            logger.error(f"获取源站组列表失败: {error_msg}")
            return {"success": False, "message": error_msg}
        else:
            origin_groups = response.get("OriginGroups", [])
            logger.info(f"获取源站组列表成功，共 {len(origin_groups)} 个源站组")
            return {"success": True, "originGroups": origin_groups}
    except Exception as e:
        logger.error(f"获取源站组列表时发生异常: {str(e)}", exc_info=True)
        return {"success": False, "message": str(e)}


# =================== 日志与配置 ===================
def setup_logging(file="task"):
    """日志初始化"""
    _logger = logging.getLogger(f"task.{file}")
    _logger.setLevel(logging.INFO)

    log_file = f"{TEMP_DIR}/eodo.{file}.log.txt"
    file_handler = RotatingFileHandler(log_file, maxBytes=200 * 1024, backupCount=1, encoding="utf-8")
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    for handler in [file_handler, console_handler]:
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        if not _logger.hasHandlers():
            _logger.addHandler(handler)
    return _logger

logger = setup_logging("task")
cron_logger = setup_logging("cron")

def get_hostname():
    """获取合法主机名"""
    pattern = r'[^a-zA-Z0-9_-]'
    name = socket.gethostname().lower()
    if re.search(pattern, name):
        raise ValueError("主机名包含不允许的字符")
    return name

hostname = get_hostname()

def read_config():
    """读取YAML配置"""
    import os
    config_path = os.environ.get('CONFIG_PATH', f"{str(HOME_DIR)}/.eodo.config.yaml")
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logger.info(f"配置文件读取成功: {config_path}")
            return config or {}
    except Exception as exc:
        logger.error(f"配置文件读取失败: {exc}")
        return {}

def write_config(config_data):
    """写入YAML配置"""
    import os
    config_path = os.environ.get('CONFIG_PATH', f"{str(HOME_DIR)}/.eodo.config.yaml")
    # 确保配置目录存在
    config_dir = os.path.dirname(config_path)
    if config_dir and not os.path.exists(config_dir):
        os.makedirs(config_dir, exist_ok=True)
    try:
        with open(config_path, 'w', encoding='utf-8') as file:
            yaml.dump(config_data, file, allow_unicode=True, default_flow_style=False)
        logger.info(f"配置保存成功: {config_path}")
        return True
    except Exception as exc:
        logger.error(f"配置保存失败: {exc}")
        return False


# =================== 腾讯云API类 ===================
class QcloudClient:
    def __init__(self, secret, service='teo', version='2022-09-01'):
        self.service: str = service
        self.host: str = f'{service}.tencentcloudapi.com'
        self.version: str = version
        self.algorithm: str = 'TC3-HMAC-SHA256'
        self.content_type: str = 'application/json; charset=utf-8'
        self.http_request_method: str = 'POST'
        self.canonical_uri: str = '/'
        self.canonical_query_string: str = ''
        self.signed_headers: str = 'content-type;host;x-tc-action'

        self.secret_id = secret.get("SecretId")
        self.secret_key = secret.get("SecretKey")

    def signature(self, action, body) -> dict:
        timestamp: int = int(time.time())
        date: str = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')

        payload = json.dumps(body)

        hashed_request_payload: str = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers: str = f'content-type:{self.content_type}\nhost:{self.host}\nx-tc-action:{action.lower()}\n'
        canonical_request: str = (self.http_request_method + '\n' +
                                  self.canonical_uri + '\n' +
                                  self.canonical_query_string + '\n' +
                                  canonical_headers + '\n' +
                                  self.signed_headers + '\n' +
                                  hashed_request_payload)

        # 拼接待签名字符串
        credential_scope = f'{date}/{self.service}/tc3_request'
        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"{self.algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

        # 计算签名
        def sign(key, message):
            return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

        secret_date = sign(('TC3' + self.secret_key).encode('utf-8'), date)
        secret_service = sign(secret_date, self.service)
        secret_signing = sign(secret_service, 'tc3_request')
        signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization = (f'{self.algorithm} '
                         f'Credential={self.secret_id}/{credential_scope}, '
                         f'SignedHeaders={self.signed_headers}, '
                         f'Signature={signature}')
        # 发送请求
        headers = {
            'Authorization': authorization,
            'Content-Type': self.content_type,
            'Host': self.host,
            'X-TC-Action': action,
            'X-TC-Version': self.version,
            'X-TC-Timestamp': str(timestamp)
        }
        return headers

    def modify_origin_group(self, zone_id, origin_group_id, origin_group_name, ipv6_addresses):
        """修改源站组配置，更新IPv6地址列表"""
        try:
            # 构建API请求参数，确保zone_id是字符串类型
            params = {
                "Action": "ModifyOriginGroup",
                "Version": "2023-05-01",
                "ZoneId": str(zone_id),
                "OriginGroupId": origin_group_id,
                "OriginGroup": {
                    "Name": origin_group_name,
                    "OriginType": "ip",
                    "Origins": []
                },
                "Type": "IP"
            }
            
            # 添加所有IPv6地址到源站配置中
            for ipv6 in ipv6_addresses:
                params["OriginGroup"]["Origins"].append({
                    "Address": ipv6,
                    "Weight": 100,
                    "Port": 80,
                    "Type": "ip"
                })
            
            logger.info(f"[{self.task_id}] 准备修改源站组: {origin_group_name}，包含 {len(ipv6_addresses)} 个IPv6地址")
            # 执行API请求
            response = self._request(params)
            
            if response.get("Response") and response["Response"].get("RequestId"):
                logger.info(f"[{self.task_id}] 源站组修改成功，请求ID: {response['Response']['RequestId']}")
                return {
                    "success": True,
                    "request_id": response["Response"]["RequestId"]
                }
            else:
                logger.error(f"[{self.task_id}] 源站组修改响应格式异常: {response}")
                return {
                    "success": False,
                    "error": "源站组修改响应格式异常"
                }
        except Exception as e:
            logger.error(f"[{self.task_id}] 修改源站组失败: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def describe_origin_group(self, zone_id):
        body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-name", "Values": [hostname]}]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {}).get('OriginGroups', {})
        
    def describe_all_origin_groups(self, zone_id):
        """获取指定ZoneID的所有源站组"""
        # 确保zone_id是字符串类型
        body = {"ZoneId": str(zone_id)}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {})

    def create_origin_group(self, zone_id, origin_group_name, ipv6_addresses):
        """创建源站组，添加IPv6地址列表"""
        try:
            # 构建API请求参数，确保zone_id是字符串类型
            params = {
                "Action": "CreateOriginGroup",
                "Version": "2023-05-01",
                "ZoneId": str(zone_id),
                "OriginGroup": {
                    "Name": origin_group_name,
                    "OriginType": "ip",
                    "Origins": []
                },
                "Type": "IP"
            }
            
            # 添加所有IPv6地址到源站配置中
            for ipv6 in ipv6_addresses:
                params["OriginGroup"]["Origins"].append({
                    "Address": ipv6,
                    "Weight": 100,
                    "Port": 80,
                    "Type": "ip"
                })
            
            logger.info(f"[{self.task_id}] 准备创建源站组: {origin_group_name}，包含 {len(ipv6_addresses)} 个IPv6地址")
            # 执行API请求
            response = self._request(params)
            
            if response.get("Response") and response["Response"].get("OriginGroupId"):
                logger.info(f"[{self.task_id}] 源站组创建成功，源站组ID: {response['Response']['OriginGroupId']}")
                return {
                    "success": True,
                    "origin_group_id": response["Response"]["OriginGroupId"],
                    "request_id": response["Response"].get("RequestId")
                }
            else:
                error = response.get("Response", {}).get("Error", {})
                error_msg = error.get("Message", "源站组创建响应格式异常")
                error_code = error.get("Code", "UnknownError")
                logger.error(f"[{self.task_id}] 源站组创建失败: {error_msg} ({error_code})")
                return {
                    "success": False,
                    "error": error_msg,
                    "error_code": error_code
                }
        except Exception as e:
            logger.error(f"[{self.task_id}] 创建源站组失败: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def modify_dns_record(self, top_domain, sub_domain, record_type, iplist, record_id):

        body = {
                "Domain": top_domain,
                "SubDomain": sub_domain,
                "RecordType": record_type,
                "RecordId": record_id,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "TTL": 600
            }
        requests.post(
            f'https://{self.host}',
            headers=self.signature("ModifyRecord", body),
            json=body
        )

    def create_dns_record(self, top_domain, sub_domain, record_type, iplist):

        body = {
                "Domain": top_domain,
                "RecordType": record_type,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "SubDomain": sub_domain,
                "TTL": 600
            }
        response = requests.post(
            f'https://{self.host}', headers=self.signature("CreateRecord", body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def delete_dns_record(self, top_domain, record_id):

        body = {"Domain": top_domain, "RecordId": record_id}
        requests.post(f'https://{self.host}', headers=self.signature("DeleteRecord", body), json=body)
        
    def describe_acceleration_domains(self, zone_id):
        """查询加速域名列表
        参考文档: https://cloud.tencent.com/document/api/1552/86336
        """
        try:
            # 构建请求参数，确保zone_id是字符串类型
            body = {
                "ZoneId": str(zone_id)
            }
            
            logger.info(f"[{self.task_id}] 查询加速域名列表，ZoneId: {zone_id}")
            
            # 发送请求
            response = requests.post(
                f'https://{self.host}', 
                headers=self.signature("DescribeAccelerationDomains", body), 
                json=body
            )
            
            # 检查HTTP状态码
            if response.status_code != 200:
                error_msg = f"HTTP请求失败，状态码: {response.status_code}, 响应内容: {response.text}"
                logger.error(f"[{self.task_id}] 查询加速域名列表失败: {error_msg}")
                return [], error_msg
            
            # 解析响应
            response_json = response.json()
            logger.info(f"[{self.task_id}] 查询加速域名列表接口响应: {response_json}")
            
            # 处理响应
            if "Response" in response_json:
                error = response_json["Response"].get("Error", {})
                if error:
                    error_msg = error.get("Message", "未知错误")
                    logger.error(f"[{self.task_id}] 查询加速域名列表失败: {error_msg}")
                    return [], error_msg
                elif "AccelerationDomains" in response_json["Response"]:
                    # 成功获取加速域名列表
                    domains = response_json["Response"]["AccelerationDomains"]
                    logger.info(f"[{self.task_id}] 查询加速域名列表成功，共 {len(domains)} 个域名")
                    return domains, ""
                else:
                    # 响应格式异常
                    error_msg = f"响应格式异常，缺少AccelerationDomains字段"
                    logger.error(f"[{self.task_id}] 查询加速域名列表失败: {error_msg}")
                    return [], error_msg
            else:
                # 响应格式异常
                error_msg = f"响应格式异常，缺少Response字段"
                logger.error(f"[{self.task_id}] 查询加速域名列表失败: {error_msg}")
                return [], error_msg
        except Exception as e:
            # 捕获所有异常
            error_msg = f"查询加速域名列表时发生异常: {str(e)}"
            logger.error(f"[{self.task_id}] {error_msg}", exc_info=True)
            return [], error_msg

    def create_acceleration_domain(self, zone_id, domain_name, origin_group_id=None, origin_address=None):
        """创建加速域名
        参考文档: https://cloud.tencent.com/document/api/1552/86338
        """
        try:
            # 构建请求参数，确保zone_id是字符串类型
            body = {
                "ZoneId": str(zone_id),
                "Domain": domain_name,
                "Type": "site"
            }
            # 源站配置，支持源站组ID或直接指定源站地址
            if origin_group_id:
                body["OriginInfo"] = {
                    "OriginGroupId": origin_group_id
                }
            elif origin_address:
                body["OriginInfo"] = {
                    "Origin": [{
                        "Record": origin_address,
                        "Type": "IP_DOMAIN"
                    }]
                }
            
            # 记录请求参数日志
            logger.info(f"[{self.task_id}] 准备创建加速域名: {domain_name}")
            logger.info(f"[{self.task_id}] 请求参数: ZoneId={zone_id}, OriginGroupId={origin_group_id}, OriginAddress={origin_address}")
            
            # 发送请求
            response = requests.post(
                f'https://{self.host}', 
                headers=self.signature("CreateAccelerationDomain", body), 
                json=body
            )
            
            # 检查HTTP状态码
            if response.status_code != 200:
                error_msg = f"HTTP请求失败，状态码: {response.status_code}, 响应内容: {response.text}"
                logger.error(f"[{self.task_id}] 创建加速域名失败: {error_msg}")
                return error_msg, f"HTTP_{response.status_code}"
            
            # 解析响应
            response_json = response.json()
            logger.info(f"[{self.task_id}] 创建加速域名接口响应: {response_json}")
            
            # 检查是否有错误
            if "Response" in response_json:
                error = response_json["Response"].get("Error", {})
                if error:
                    error_msg = error.get("Message", "未知错误")
                    error_code = error.get("Code", "UnknownError")
                    logger.error(f"[{self.task_id}] 创建加速域名失败: {error_msg} (错误码: {error_code})")
                    return error_msg, error_code
                elif "AccelerationDomain" in response_json["Response"]:
                    # 成功创建
                    logger.info(f"[{self.task_id}] 加速域名创建成功: {domain_name}")
                    return "", ""
                else:
                    # 响应格式异常
                    error_msg = f"响应格式异常，缺少AccelerationDomain字段: {response_json}"
                    logger.error(f"[{self.task_id}] 创建加速域名失败: {error_msg}")
                    return error_msg, "InvalidResponse"
            else:
                # 响应格式异常
                error_msg = f"响应格式异常，缺少Response字段: {response_json}"
                logger.error(f"[{self.task_id}] 创建加速域名失败: {error_msg}")
                return error_msg, "InvalidResponse"
        except Exception as e:
            # 捕获所有异常
            error_msg = f"创建加速域名时发生异常: {str(e)}"
            logger.error(f"[{self.task_id}] {error_msg}", exc_info=True)  # 记录完整堆栈
            return error_msg, "Exception"
        finally:
            logger.debug(f"[{self.task_id}] 创建加速域名操作完成")


# =================== API路由 ===================
@app.post("/api/create-accel-domain")
async def create_accel_domain(request: Request):
    """创建加速域名API"""
    try:
        data = await request.json()
        zone_id = data.get("zoneId")
        domain_name = data.get("domainName")
        origin_group_id = data.get("originGroupId")
        origin_address = data.get("originAddress")
        origin_protocol = data.get("originProtocol", "FOLLOW")
        http_origin_port = data.get("httpOriginPort", 80)
        https_origin_port = data.get("httpsOriginPort", 443)
        ipv6_status = data.get("ipv6Status", "follow")  # 获取IPv6状态，默认为遵循站点配置
        
        if not zone_id or not domain_name:
            return {"success": False, "message": "缺少必要参数"}
        
        # 读取配置
        config = read_config()
        secret = config.get("secret", {})
        if not secret:
            return {"success": False, "message": "未配置腾讯云密钥"}
        
        # 创建客户端并调用创建接口
        client = QcloudClient(secret)
        
        # 构建创建请求
        body = {
            "ZoneId": zone_id,
            "Domain": domain_name,
            "Type": "site"
        }
        
        # 源站配置
        if origin_group_id:
            body["OriginInfo"] = {
                "OriginGroupId": origin_group_id
            }
        elif origin_address:
            body["OriginInfo"] = {
                "Origin": [{
                    "Record": origin_address,
                    "Type": "IP_DOMAIN"
                }]
            }
        
        # 回源配置
        origin_config = {
            "OriginProtocol": origin_protocol,
        }
        
        # 添加端口配置
        if origin_protocol == "FOLLOW" or origin_protocol == "HTTP":
            origin_config["HttpOriginPort"] = http_origin_port
        
        if origin_protocol == "FOLLOW" or origin_protocol == "HTTPS":
            origin_config["HttpsOriginPort"] = https_origin_port
        
        body["OriginInfo"]["OriginConfig"] = origin_config
        
        # 添加IPv6状态配置
        body["IPv6Status"] = ipv6_status
        
        logger.info(f"准备创建加速域名: {domain_name}")
        logger.info(f"请求参数: {body}")
        
        # 调用创建接口
        response = requests.post(
            f'https://{client.host}',
            headers=client.signature("CreateAccelerationDomain", body),
            json=body
        )
        
        if response.status_code != 200:
            error_msg = f"HTTP请求失败，状态码: {response.status_code}"
            logger.error(error_msg)
            return {"success": False, "message": error_msg}
        
        response_json = response.json()
        logger.info(f"创建加速域名接口响应: {response_json}")
        
        # 检查是否有错误
        if "Response" in response_json:
            error = response_json["Response"].get("Error", {})
            if error:
                error_msg = error.get("Message", "未知错误")
                logger.error(f"创建加速域名失败: {error_msg}")
                return {"success": False, "message": error_msg}
            else:
                logger.info(f"加速域名创建成功: {domain_name}")
                return {"success": True}
        else:
            return {"success": False, "message": "响应格式异常"}
    
    except Exception as e:
        logger.error(f"创建加速域名时发生异常: {str(e)}", exc_info=True)
        return {"success": False, "message": str(e)}


@app.post("/api/delete-accel-domain")
async def delete_accel_domain(request: Request):
    """删除加速域名API"""
    try:
        data = await request.json()
        zone_id = data.get("zoneId")
        domain_name = data.get("domainName")
        
        if not zone_id or not domain_name:
            return {"success": False, "error": "缺少必要参数"}
        
        # 读取配置
        config = read_config()
        secret = config.get("secret", {})
        if not secret:
            return {"success": False, "error": "未配置腾讯云密钥"}
        
        # 创建客户端并调用删除接口
        client = QcloudClient(secret)
        
        # 构建删除请求（根据腾讯云文档：https://cloud.tencent.com/document/api/1552/86337）
        body = {
            "ZoneId": zone_id,
            "DomainNames": [domain_name],  # 使用DomainNames数组参数
            "Force": False  # 可选参数：是否强制删除
        }
        
        logger.info(f"准备删除加速域名: {domain_name}")
        
        # 调用删除接口（使用正确的Action名称：DeleteAccelerationDomains）
        response = requests.post(
            f'https://{client.host}',
            headers=client.signature("DeleteAccelerationDomains", body),
            json=body
        )
        
        if response.status_code != 200:
            error_msg = f"HTTP请求失败，状态码: {response.status_code}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
        
        response_json = response.json()
        logger.info(f"删除加速域名接口响应: {response_json}")
        
        # 检查是否有错误
        if "Response" in response_json:
            error = response_json["Response"].get("Error", {})
            if error:
                error_msg = error.get("Message", "未知错误")
                logger.error(f"删除加速域名失败: {error_msg}")
                return {"success": False, "error": error_msg}
            else:
                logger.info(f"加速域名删除成功: {domain_name}")
                return {"success": True}
        else:
            return {"success": False, "error": "响应格式异常"}
    
    except Exception as e:
        logger.error(f"删除加速域名时发生异常: {str(e)}", exc_info=True)
        return {"success": False, "error": str(e)}


# 确保QcloudClient类有task_id属性
class QcloudClient(QcloudClient):
    def __init__(self, secret, service='teo', version='2022-09-01'):
        super().__init__(secret, service, version)
        self.task_id = str(uuid.uuid4())

    def _request(self, params):
        """发送API请求"""
        try:
            action = params.get("Action")
            headers = self.signature(action, params)
            response = requests.post(
                f'https://{self.host}',
                headers=headers,
                json=params
            )
            return response.json()
        except Exception as e:
            logger.error(f"[{self.task_id}] API请求失败: {str(e)}")
            return {"Response": {"Error": {"Message": str(e)}}}


# 缺失的函数定义
class TaskScheduler:
    def __init__(self, interval_min):
        self.interval_min = interval_min
    
    def start_scheduler(self):
        pass

def load_interval():
    return 5  # 默认5分钟


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口')

    args = parser.parse_args()
    global scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()




