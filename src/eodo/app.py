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

from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


# =================== 常量与路径 ===================
HOME_DIR = Path.home()
# 使用/app/config作为持久化存储目录（Docker挂载路径）
TEMP_DIR = "/app/config"
# 确保配置目录存在
config_dir = Path(TEMP_DIR)
try:
    config_dir.mkdir(exist_ok=True, parents=True)
    print(f"配置目录已确保存在: {TEMP_DIR}")
except PermissionError:
    # 如果在Docker外部运行时没有权限创建/app/config，则回退到临时目录
    print(f"警告: 无法创建目录 {TEMP_DIR}，回退到临时目录")
    TEMP_DIR = tempfile.gettempdir()
    config_dir = Path(TEMP_DIR)
    config_dir.mkdir(exist_ok=True, parents=True)
    print(f"使用临时目录: {TEMP_DIR}")
CURRENT_DIR = Path(__file__).parent
STATIC_PATH = CURRENT_DIR / "static"
STATIC_PATH.mkdir(exist_ok=True)
print(STATIC_PATH)
print(TEMP_DIR)


# =================== 日志与配置 ===================
def setup_logging(file="task"):
    """日志初始化 - 支持持久化存储到/app/config目录"""
    _logger = logging.getLogger(f"task.{file}")
    _logger.setLevel(logging.INFO)

    # 使用Path对象构建日志文件路径，更健壮的路径处理
    log_file_path = Path(TEMP_DIR) / f"eodo.{file}.log.txt"
    log_file = str(log_file_path)
    
    try:
        # 尝试创建RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=200 * 1024,  # 200KB
            backupCount=5,        # 增加备份数量到5个
            encoding="utf-8"
        )
        # 配置文件处理器
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        print(f"日志文件已配置: {log_file}")
    except Exception as e:
        # 如果文件处理器创建失败，仅使用控制台日志
        print(f"警告: 无法创建日志文件 {log_file}: {str(e)}")
        file_handler = None
    
    # 配置控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    
    # 清除现有处理器并添加新处理器
    if _logger.hasHandlers():
        _logger.handlers.clear()
    
    if file_handler:
        _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)
    
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
    config_path = f"{str(HOME_DIR)}/.eodo.config.yaml"
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except Exception as exc:
        logger.error(f"配置文件读取失败: {exc}")
        return {}


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

    def modify_origin_group(self, zone_id, origin_group_id, iplist):
        body = {"ZoneId": zone_id, "GroupId": origin_group_id,
                "Records": [{"Record": ip, "Type": "IP_DOMAIN", "Weight": 100} for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('ModifyOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def describe_origin_group(self, zone_id):
        body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-name", "Values": [hostname]}]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {}).get('OriginGroups', {})
        
    def describe_all_origin_groups(self, zone_id):
        """获取指定ZoneID的所有源站组"""
        body = {"ZoneId": zone_id}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {})

    def create_origin_group(self, zone_id, iplist):
        body = {"ZoneId": zone_id, "Name": hostname, "Type": "GENERAL",
                "Records": [{"Record": ip, "Type": "IP_DOMAIN"} for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('CreateOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

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

    def create_acceleration_domain(self, zone_id, domain_name, origin_type="IP_DOMAIN", origin_group_id=None, origin_address=None, ipv6_status="follow", origin_protocol="FOLLOW", http_origin_port=80, https_origin_port=443):
        """创建加速域名
        参考文档: https://cloud.tencent.com/document/api/1552/86338
        """
        try:
            # 参数验证
            if not zone_id or not domain_name:
                return "ZoneId和DomainName不能为空", "MissingParameters"
            
            if origin_type == "ORIGIN_GROUP" and not origin_group_id:
                return "源站组ID不能为空", "MissingOriginGroupId"
            if origin_type == "IP_DOMAIN" and not origin_address:
                return "源站地址不能为空", "MissingOriginAddress"
            
            # 构建请求体
            body = {
                "ZoneId": str(zone_id).strip(),
                "DomainName": str(domain_name).strip(),
                "IPv6Status": ipv6_status,
                "OriginProtocol": origin_protocol
            }
            
            # 设置端口
            if origin_protocol in ["FOLLOW", "HTTP"]:
                body["HttpOriginPort"] = http_origin_port    
            if origin_protocol in ["FOLLOW", "HTTPS"]:
                body["HttpsOriginPort"] = https_origin_port
            
            # 设置源站信息
            origin_value = origin_group_id if origin_type == "ORIGIN_GROUP" else origin_address
            body["OriginInfo"] = {
                "OriginType": origin_type,
                "Origin": str(origin_value).strip()
            }
            
            # 发送请求
            response = requests.post(
                f'https://{self.host}', 
                headers=self.signature("CreateAccelerationDomain", body), 
                json=body
            )
            
            # 处理HTTP响应
            if response.status_code != 200:
                error_msg = f"HTTP请求失败，状态码: {response.status_code}, 响应内容: {response.text}"
                print(f"创建加速域名失败: {error_msg}")
                return error_msg, f"HTTP_{response.status_code}"
            
            # 解析响应
            response_json = response.json()
            print(f"创建加速域名接口响应: {response_json}")
            
            # 检查是否有错误
            if "Response" in response_json:
                error = response_json["Response"].get("Error", {})
                if error:
                    error_msg = error.get("Message", "未知错误")
                    error_code = error.get("Code", "UnknownError")
                    print(f"创建加速域名失败: {error_msg} (错误码: {error_code})")
                    return error_msg, error_code
                # 腾讯云API响应可能不包含AccelerationDomain字段，但只要没有错误且有RequestId，就应该认为成功
                elif "RequestId" in response_json["Response"]:
                    # 成功创建
                    request_id = response_json["Response"]["RequestId"]
                    print(f"加速域名创建成功: {domain_name}, RequestId: {request_id}")
                    return "", ""
                else:
                    # 响应格式异常
                    error_msg = f"响应格式异常，缺少RequestId字段: {response_json}"
                    print(f"创建加速域名失败: {error_msg}")
                    return error_msg, "InvalidResponse"
            else:
                # 响应格式异常
                error_msg = f"响应格式异常，缺少Response字段: {response_json}"
                print(f"创建加速域名失败: {error_msg}")
                return error_msg, "InvalidResponse"
                
        except Exception as e:
            # 捕获所有异常
            error_msg = f"创建加速域名时发生异常: {str(e)}"
            print(f"{error_msg}", exc_info=True)  # 记录完整堆栈
            return error_msg, "Exception"
        finally:
            print(f"创建加速域名操作完成")

    def describe_dns_record(self, top_domain, sub_domain, record_type):

        body = {
                "Domain": top_domain,
                "Subdomain": sub_domain,
                "RecordType": record_type,
            }
        responses = requests.post(
            f'https://{self.host}',
            headers=self.signature("DescribeRecordList", body),
            json=body
        ).json().get('Response').get('RecordList', [])
        return responses


# =================== 工具类 ===================
class IPv4Tool:
    """处理IPv4地址的工具类"""
    def __init__(self, custom_ip_list=None):
        self.custom_ip_list = custom_ip_list or []
    
    def get_ipv4_list(self):
        """获取IPv4地址列表，包括自定义IPv4地址"""
        ipv4_list = []
        
        # 添加用户自定义的IPv4地址
        if self.custom_ip_list:
            for custom_ip in self.custom_ip_list:
                try:
                    # 验证是否为有效的IPv4地址
                    ipaddress.IPv4Address(custom_ip)
                    ipv4_list.append(custom_ip)
                except ValueError:
                    logger.warning(f"无效的IPv4地址: {custom_ip}")
        
        return set(ipv4_list)

class IPv6Tool:
    def __init__(self, select_iface="", task_id="", ipv6_regex="", custom_ip_list=None):
        self.task_id = task_id
        self.ipv6_regex = ipv6_regex
        self.custom_ip_list = custom_ip_list or []
        self.public_ipv6:set[str]|None = self.get_ipv6_list(select_iface)

    def get_ipv6_list(self, select_iface=""):
        # 首先获取所有公网IPv6地址（不进行ping测试）
        all_ipv6_list = []
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if select_iface and iface != select_iface:
                continue
            for addr in addr_list:
                ip = addr.address.split('%')[0]
                if addr.family == socket.AF_INET6 and self.is_public_ipv6(ip):
                    all_ipv6_list.append(ip)
        
        # 按字母顺序排序
        sorted_ipv6_list = sorted(all_ipv6_list)
        
        # 如果没有找到IPv6地址，直接返回None
        if not sorted_ipv6_list:
            logger.info(f"[{self.task_id}] 未找到公网IPv6地址")
            return None
        
        logger.info(f"[{self.task_id}] 共找到 {len(sorted_ipv6_list)} 个公网IPv6地址")
        
        # 根据用户是否选择了IPv6地址决定不同的检查逻辑
        if self.ipv6_regex:
            selected_ip = None
            
            # 处理索引格式 @1, @2 等
            if self.ipv6_regex.startswith('@'):
                try:
                    index = int(self.ipv6_regex[1:]) - 1  # 转为0-based索引
                    if 0 <= index < len(sorted_ipv6_list):
                        selected_ip = sorted_ipv6_list[index]
                        logger.info(f"[{self.task_id}] 通过索引 {self.ipv6_regex} 选择IPv6地址: {selected_ip}")
                        # 对于用户选择的地址，不需要进行ping测试，直接返回该地址
                        # 因为网卡自动获得的地址可能会有更新，我们只需要检查这个位置的地址是否存在
                        return set([selected_ip])
                    else:
                        logger.warning(f"[{self.task_id}] 索引 {self.ipv6_regex} 超出范围，索引范围应为 @1 到 @{len(sorted_ipv6_list)}")
                except ValueError:
                    logger.warning(f"[{self.task_id}] 无效的索引格式: {self.ipv6_regex}，正确格式应为 @1, @2 等")
            # 处理正则表达式格式
            else:
                try:
                    pattern = re.compile(self.ipv6_regex)
                    selected_ip = next((ip for ip in sorted_ipv6_list if pattern.search(ip)), None)
                    if selected_ip:
                        logger.info(f"[{self.task_id}] 通过正则表达式 '{self.ipv6_regex}' 选择IPv6地址: {selected_ip}")
                        # 对于用户通过正则选择的地址，直接返回
                        return set([selected_ip])
                    else:
                        logger.warning(f"[{self.task_id}] 未能通过正则表达式 '{self.ipv6_regex}' 匹配到任何IPv6地址")
                except re.error:
                    logger.warning(f"[{self.task_id}] 无效的正则表达式: {self.ipv6_regex}")
            
            logger.warning(f"[{self.task_id}] IPv6地址选择失败，将回退到ping测试方式")
        
        # 用户没有选择IPv6地址或选择失败，对所有地址进行ping测试
        logger.info(f"[{self.task_id}] 用户未选择IPv6地址或选择失败，正在对所有IPv6地址进行ping测试")
        pinged_ips = []
        for ip in sorted_ipv6_list:
            if self.public_ipv6_check(ip):
                pinged_ips.append(ip)
        
        if not pinged_ips:
            logger.warning(f"[{self.task_id}] 所有IPv6地址都无法通过ping测试")
            return None
        else:
            logger.info(f"[{self.task_id}] 共有 {len(pinged_ips)} 个IPv6地址通过了ping测试")
            return set(pinged_ips)

    @staticmethod
    def is_public_ipv6(ip):
        try:
            addr = ipaddress.IPv6Address(ip)
            return not (addr.is_link_local or addr.is_private or addr.is_loopback or addr.is_unspecified)
        except ValueError:
            return False  # 非法IP，就认为不是公网

    def public_ipv6_check(self, ip):
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.54"

        def ipw_cn():
            try:
                res = requests.get(
                    f"https://ipw.cn/api/ping/ipv6/{ip}/1/all",
                    headers={"User-Agent": user_agent},
                    timeout=5
                )
                if '"lossPacket":0' in res.text:
                    logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 无丢包")
                    return True
                else:
                    logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 超时")
                    return False
            except Exception as e:
                logger.debug(e)
                logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 超时或异常")
                return False
        def ping6_network():
            try:
                res = requests.get(
                    f"https://ping6.network/index.php?host={ip.replace(':', '%3A')}",
                    headers={"User-Agent": user_agent},
                    timeout=15
                )
                if ', 0% packet loss' in res.text:
                    logger.info(f"[{self.task_id}] ping6.network Ping [{ip}] 无丢包")
                    return True
                else:
                    logger.info(f"[{self.task_id}] ping6.network Ping {ip} 超时")
                    return False
            except Exception as e:
                logger.debug(e)
                logger.info(f"[{self.task_id}] ping6.network Ping {ip} 超时或异常")
                return False

        return True if ipw_cn() else ping6_network()


# =================== 钉钉通知类 ===================
class Dingtalk:
    def __init__(self, webhook):
        self.webhook = webhook

    def notice_no_public_ipv6(self):
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "无法获取IP",
                    "text": f"> 信息：{hostname}无法获取公网IPv6，跳过此次更新。"
                },
                "msgtype": "markdown"
            })

    def notice_eo_result(self, site_tag:str, zone_id:str, public_ipv6:List[str], message:str):
        ipv6_text = [f"- {item}\n" for item in public_ipv6]

        ipv6_content = '\n'.join(ipv6_text)
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "EdgeOne源站更新",
                    "text": f"### EdgeOne源站更新\n\n"
                            f"**标签：** {site_tag}\n\n"
                            f"**站点：** {zone_id}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** \n\n{ipv6_content}"
                }, "msgtype": "markdown"}
        )

    def notice_dns_result(self, domain:str, public_ipv6:List[str], message:str):

        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "DNS解析更新",
                    "text": f"### DNS解析更新\n\n"
                            f"**域名：** {domain}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** {public_ipv6[0]}"
                }, "msgtype": "markdown"}
        )

# =================== 任务处理 ===================
def update_task(task_id=""):
    config = read_config()
    # 获取自定义IP列表，如果配置中不存在则为空列表
    custom_ip_list = config.get("CustomIPList", [])
    # 确保custom_ip_list是列表类型
    if not isinstance(custom_ip_list, list):
        custom_ip_list = []
    
    # 分离IPv4和IPv6处理
    ipv4_tool = IPv4Tool(custom_ip_list=custom_ip_list)
    ipv6_tool = IPv6Tool(
        select_iface=config.get("SelectIface"), 
        task_id=task_id, 
        ipv6_regex=config.get("IPv6Regex")
    )
    
    # 获取IPv4和IPv6地址列表
    ipv4_addresses = ipv4_tool.get_ipv4_list()
    ipv6_addresses = ipv6_tool.public_ipv6 or set()
    
    # 合并所有地址
    all_addresses = ipv4_addresses.union(ipv6_addresses)
    
    dingtalk = Dingtalk(config.get('DingTalkWebhook'))
    eo_zones = config.get("EdgeOneZoneId")
    domains = config.get('DnsPodRecord')
    qcloud_secret = config.get('TencentCloud')

    if not all_addresses:
        logger.info(f"[{task_id}] 无法获取任何IP地址，跳过后续所有步骤。")
        dingtalk.notice_no_public_ipv6()
        return
    else:
        all_addresses_str = ','.join(all_addresses)
        # 记录包含自定义IP的完整地址列表
        if custom_ip_list:
            logger.info(f"[{task_id}] 获取IP地址成功（包含 {len(custom_ip_list)} 个自定义IP），完整地址为：{all_addresses_str}")
        else:
            logger.info(f"[{task_id}] 获取IP地址成功，地址为：{all_addresses_str}")

    if eo_zones:
        eo_client = QcloudClient(secret=qcloud_secret, service='teo', version='2022-09-01')
        for zone in eo_zones:
            origin_groups = eo_client.describe_origin_group(zone)

            if len(origin_groups) >= 1:
                group_id = origin_groups[0].get('GroupId')
                old_list = [i.get('Record') for i in origin_groups[0].get('Records')]
                old_list.sort()
                records = set(old_list)

                if all_addresses == records:
                    logger.info(f"[{task_id}] IP 地址列表未发生变更，站点 {zone} 的源站组 {hostname} 无需更新。")
                else:
                    logger.info(f"[{task_id}] IP 地址列表发生变更，新的地址： {all_addresses}")
                    error_msg, error_code = eo_client.modify_origin_group(zone, group_id, all_addresses)
                    error_msg = f"成功更新站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                    logger.info(f"[{task_id}] {error_msg} {error_code}")
                    dingtalk.notice_eo_result(hostname, zone, list(all_addresses), error_msg)
            else:
                logger.info(f"[{task_id}] 站点 {zone} 的源站组 {hostname} 尚未未创建。")
                error_msg, error_code = eo_client.create_origin_group(zone, all_addresses)
                error_msg = f"成功创建站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
                dingtalk.notice_eo_result(hostname, zone, list(all_addresses), error_msg)

    if domains:
        dnspod = QcloudClient(secret=qcloud_secret, service='dnspod', version='2021-03-23')

        for domain in domains:
            sub_domain, record_type, top_domain = domain.split('|')
            fqdn = '.'.join([sub_domain, top_domain])
            records = dnspod.describe_dns_record(top_domain, sub_domain, record_type)
            record_counts = len(records)

            for record in records:
                if record["Value"] not in list(all_addresses):
                    logger.info(f"[{task_id}] 站点 {fqdn} 存在已过期的解析记录 {record['Value']} , 正在删除。")
                    dnspod.delete_dns_record(top_domain, record['RecordId'])
                    record_counts -= 1

            if record_counts >= 1:
                logger.info(f"[{task_id}] 站点 {fqdn} 查询到至少存在一条有效解析记录, 跳过解析更改。")
            else:
                logger.info(f"[{task_id}] 站点 {fqdn} 不存在可用的解析记录，正在新建解析。")
                error_msg, error_code = dnspod.create_dns_record(top_domain, sub_domain, record_type, all_addresses)
                error_msg = f"成功更新解解析记录 {fqdn} " if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
                dingtalk.notice_dns_result(fqdn, list(all_addresses), error_msg)

# 存储上一次的IP地址列表用于变化检测
last_ip_addresses = set()
last_status = {"id":"", "result":"等待"}

def run_task_in_background():
    task_id = str(uuid.uuid4())
    try:
        cron_logger.info(f"[{task_id}] 启动")
        
        # 检查IP地址是否发生变化
        global last_ip_addresses
        current_addresses = get_current_ip_addresses()
        
        if current_addresses != last_ip_addresses:
            cron_logger.info(f"[{task_id}] IP地址发生变化，执行更新任务")
            cron_logger.info(f"[{task_id}] 旧地址: {last_ip_addresses}")
            cron_logger.info(f"[{task_id}] 新地址: {current_addresses}")
            update_task(task_id=task_id)
            last_ip_addresses = current_addresses
            cron_logger.info(f"[{task_id}] 结束")
            last_status.update({"id": task_id, "result": "结束"})
        else:
            cron_logger.info(f"[{task_id}] IP地址未发生变化，跳过更新")
            last_status.update({"id": task_id, "result": "跳过"})
            
    except Exception as e:
        logger.debug(e)
        cron_logger.error(f"[{task_id}] 异常")
        last_status.update({"id": task_id, "result": "异常"})

def get_current_ip_addresses():
    """获取当前的IP地址列表（IPv4 + IPv6）"""
    try:
        config = read_config()
        custom_ip_list = config.get("CustomIPList", [])
        
        # 处理IPv4地址
        ipv4_tool = IPv4Tool(custom_ip_list)
        ipv4_addresses = ipv4_tool.get_ipv4_list()
        
        # 处理IPv6地址
        ipv6_tool = IPv6Tool()
        ipv6_addresses = ipv6_tool.get_ipv6_list()
        
        # 合并地址列表
        all_addresses = ipv4_addresses.union(ipv6_addresses)
        
        return all_addresses
    except Exception as e:
        logger.error(f"获取当前IP地址失败: {str(e)}")
        return set()

def load_interval(default_interval=15):
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    if os.path.exists(cfgfile):
        with open(cfgfile, "r", encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f)
                interval = int(config.get("IntervalMin", 15))
                if interval < 1: interval = 1
                return interval
            except Exception as e:
                logger.debug(e)
    return default_interval  # 默认值

class TaskScheduler:
    def __init__(self, interval_min=15):
        self.interval_min = interval_min
        self.scheduler_thread = None
        self.scheduler_stop_flag = threading.Event()
        self.lock = threading.Lock()

    def scheduler_loop(self):
        while not self.scheduler_stop_flag.is_set():
            run_task_in_background()
            for _ in range(self.get_interval() * 60):
                if self.scheduler_stop_flag.is_set():
                    return
                time.sleep(1)

    def get_interval(self):
        with self.lock:
            return self.interval_min

    def set_interval(self, interval_min):
        if interval_min < 1:
            interval_min = 1
        with self.lock:
            self.interval_min = interval_min

    def start_scheduler(self):
        if self.scheduler_thread is None or not self.scheduler_thread.is_alive():
            self.scheduler_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
            self.scheduler_thread.start()

    def restart_scheduler(self, interval_min):
        self.scheduler_stop_flag.set()
        self.scheduler_thread = None
        self.set_interval(interval_min)
        self.scheduler_stop_flag.clear()
        self.start_scheduler()

# 声明全局定时器
scheduler:TaskScheduler = None


# =================== FastAPI 路由 ===================
app = FastAPI()


@app.get("/", response_class=HTMLResponse)
async def read_root():
    return FileResponse(str(STATIC_PATH / "index.html"))

# 提供静态文件服务
app.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")


@app.get('/api/status')
def api_status():
    # 简单读取
    log_file = f"{TEMP_DIR}/eodo.cron.log.txt"
    if not os.path.exists(log_file):
        return last_status
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in reversed(f.readlines()):
            if "] " in line:
                tid = line.split("]")[0].split("[")[-1]
                if "异常" in line:
                    return {"id": tid, "result": "异常", "time": line[:19]}
                if "结束" in line:
                    return {"id": tid, "result": "结束", "time": line[:19]}
                if "跳过" in line:
                    return {"id": tid, "result": "跳过", "time": line[:19]}
                if "启动" in line:
                    return {"id": tid, "result": "启动", "time": line[:19]}
    return last_status

@app.post('/api/run-task')
def api_run(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_task_in_background)
    return {"msg": "已触发"}

@app.get('/api/iface')
def api_iface():
    return list(psutil.net_if_addrs().keys())

@app.get('/api/ipv6-addresses')
def api_ipv6_addresses(iface: str = None):
    """获取指定网络接口的IPv6地址列表"""
    ipv6_addresses = []
    addrs = psutil.net_if_addrs()
    
    # 如果指定了接口且存在
    if iface and iface in addrs:
        interfaces = [iface]
    else:
        # 否则返回所有接口
        interfaces = addrs.keys()
    
    for interface in interfaces:
        for addr in addrs[interface]:
            ip = addr.address.split('%')[0]
            if addr.family == socket.AF_INET6 and IPv6Tool.is_public_ipv6(ip):
                ipv6_addresses.append(ip)
    
    return sorted(ipv6_addresses)

@app.get('/api/config')
def get_config():
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    if not os.path.exists(cfgfile):
        return {}
    with open(cfgfile, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

@app.post('/api/config')
async def post_config(request: Request):
    data = await request.json()
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    # 允许配置 IntervalMin
    interval = data.get("IntervalMin", None)
    with open(cfgfile, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True)
    # 如果带了 IntervalMin，同步到调度器
    if interval is not None:
        try:
            scheduler.restart_scheduler(int(interval))
        except Exception as e:
            logger.debug(e)
    return {"msg": "配置已保存"}

@app.get('/api/logs')
def get_logs():
    log_file = f"{TEMP_DIR}/eodo.task.log.txt"
    if os.path.exists(log_file):
        lines = open(log_file, encoding="utf-8").readlines()[-100:]
        return {"logs": "".join(lines)}
    return {"logs": ""}

@app.post('/api/interval')
async def set_interval(request: Request):
    data = await request.json()
    val = int(data.get("interval", 15))
    if val < 1: val = 1
    # 修改调度器周期
    if scheduler is None:
        return {"msg": "调度器未初始化，请重启应用"}
    scheduler.restart_scheduler(val)
    # 保存到配置文件
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    config = {}
    if os.path.exists(cfgfile):
        with open(cfgfile, "r", encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.debug(e)
                config = {}
    config["IntervalMin"] = val
    with open(cfgfile, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    return {"msg": "已设置周期间隔"}

@app.get("/api/accel-domains")
def get_accel_domains():
    try:
        # 从配置文件中读取已保存的加速域名列表
        config = read_config()
        accel_domains = config.get("AccelDomains", [])
        return {"success": True, "domains": accel_domains}
    except Exception as e:
        logger.error(f"获取加速域名列表失败: {str(e)}")
        return {"success": False, "message": str(e)}

@app.get("/api/origin-groups/{zone_id}")
async def get_origin_groups(zone_id: str):
    """获取指定ZoneID的源站组列表"""
    try:
        # 加载配置
        config = read_config()
        
        # 检查是否有腾讯云密钥配置
        if not config.get("TencentCloud") or not config["TencentCloud"].get("SecretId") or not config["TencentCloud"].get("SecretKey"):
            logger.error("请先配置腾讯云密钥")
            return {"success": False, "message": "请检查腾讯云SecretId和SecretKey配置是否正确"}
        
        # 创建QcloudClient实例
        client = QcloudClient(config["TencentCloud"])
        
        # 调用API获取源站组列表
        response = client.describe_all_origin_groups(zone_id)
        
        # 检查是否有错误
        if "Error" in response:
            error_msg = response["Error"].get("Message", "获取源站组失败")
            logger.error(f"获取源站组失败: {error_msg}")
            # 统一错误提示格式
            return {"success": False, "message": f"请检查SecretId、SecretKey和EdgeOne站点配置的ZoneID({zone_id})是否正确"}
        
        # 格式化返回数据
        origin_groups = response.get("OriginGroups", [])
        groups_data = [{
            "groupId": group.get("GroupId"),
            "name": group.get("Name"),
            "type": group.get("Type")
        } for group in origin_groups]
        
        return {"success": True, "originGroups": groups_data}
    except Exception as e:
        logger.error(f"获取源站组列表失败: {str(e)}")
        # 统一异常情况下的错误提示
        return {"success": False, "message": f"获取源站组失败，请检查SecretId、SecretKey和EdgeOne站点配置的ZoneID是否正确"}


def _save_accel_domain_to_config(zone_id, domain_name, data):
    """将加速域名保存到配置文件"""
    config = read_config()
    
    # 构建加速域名配置
    accel_domain = {
        "zoneId": zone_id,
        "domainName": domain_name,
        "originProtocol": data.get("originProtocol", "FOLLOW"),
        "originType": data.get("originType", "ip")
    }
    
    # 根据类型添加对应的源站信息
    if data.get("originType") == "group":
        accel_domain["originGroupId"] = data.get("originGroupId")
    else:
        accel_domain["originAddress"] = data.get("originAddress")
    
    # 获取现有列表并检查重复
    accel_domains = config.get("AccelDomains", [])
    for domain in accel_domains:
        if domain["domainName"] == domain_name and domain["zoneId"] == zone_id:
            raise ValueError("该加速域名已存在")
    
    # 添加新记录
    accel_domains.append(accel_domain)
    config["AccelDomains"] = accel_domains
    
    # 保存配置
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    with open(cfgfile, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

@app.post("/api/create-accel-domain")
async def create_accel_domain(request: Request):
    try:
        data = await request.json()
        zone_id = data.get("zoneId")
        domain_name = data.get("domainName")
        origin_type_param = data.get("originType", "ip")  # "group" 或 "ip"
        origin_group_id = data.get("originGroupId")
        origin_address = data.get("originAddress")
        # 基本验证
        if not zone_id or not domain_name:
            return {"success": False, "message": "站点ZoneID和加速域名不能为空"}
        
        # 源站验证
        if origin_type_param == "group" and not origin_group_id:
            return {"success": False, "message": "源站组ID不能为空"}
        if origin_type_param == "ip" and not origin_address:
            return {"success": False, "message": "源站地址不能为空"}
        
        # 加载配置
        config = read_config()
        qcloud_secret = config.get('TencentCloud')
        if not qcloud_secret or not qcloud_secret.get("SecretId") or not qcloud_secret.get("SecretKey"):
            return {"success": False, "message": "未配置腾讯云密钥"}
        # 创建客户端并调用
        client = QcloudClient(qcloud_secret)
        
        # 转换origin_type参数
        origin_type = "ORIGIN_GROUP" if origin_type_param == "group" else "IP_DOMAIN"
        
        # 调用客户端方法
        error_msg, error_code = client.create_acceleration_domain(
            zone_id=zone_id,
            domain_name=domain_name,
            origin_type=origin_type,
            origin_group_id=origin_group_id,
            origin_address=origin_address,
            ipv6_status=data.get("ipv6Status", "follow"),
            origin_protocol=data.get("originProtocol", "FOLLOW"),
            http_origin_port=data.get("httpOriginPort", 80),
            https_origin_port=data.get("httpsOriginPort", 443)
        )
        if error_msg:
            return {"success": False, "message": f"创建加速域名失败: {error_msg}"}
        
        # 保存到配置文件中
        _save_accel_domain_to_config(zone_id, domain_name, data)
        
        return {"success": True, "message": "创建加速域名成功"}
        
    except Exception as e:
        logger.error(f"创建加速域名失败: {str(e)}")
        return {"success": False, "message": "创建加速域名失败，请检查配置信息"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口')

    args = parser.parse_args()
    global scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
    uvicorn.run(app, host="0.0.0.0", port=args.port)


# 在模块加载时初始化scheduler，避免uvicorn重载时丢失
if __name__ == "__main__":
    main()
else:
    # 当作为模块导入时也初始化scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
