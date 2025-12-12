import os
import yaml
import tempfile
import shutil

# 测试配置持久化功能
def test_config_persistence():
    # 创建临时目录模拟挂载卷
    temp_dir = tempfile.mkdtemp()
    try:
        # 设置环境变量指向临时目录
        os.environ['CONFIG_PATH'] = os.path.join(temp_dir, 'eodo.config.yaml')
        print(f"测试配置文件路径: {os.environ['CONFIG_PATH']}")
        
        # 模拟初始化配置文件
        def init_config():
            config_path = os.environ.get('CONFIG_PATH')
            # 确保目录存在
            config_dir = os.path.dirname(config_path)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            # 创建默认配置
            default_config = {
                "TencentCloud": {"SecretId": "", "SecretKey": ""},
                "EdgeOne": {"ZoneId": []},
                "DnsPod": {"Record": []},
                "DingTalk": {"Webhook": ""},
                "Interval": 5,
                "SelectIface": "",
                "IPv6Regex": "",
                "CustomIPList": []
            }
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, allow_unicode=True)
            print(f"初始化默认配置文件: {config_path}")
            return default_config
        
        # 模拟读取配置
        def read_config():
            config_path = os.environ.get('CONFIG_PATH')
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"读取配置失败: {e}")
                return None
        
        # 模拟写入配置
        def write_config(config_data):
            config_path = os.environ.get('CONFIG_PATH')
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, allow_unicode=True, default_flow_style=False)
                print(f"配置保存成功: {config_path}")
                return True
            except Exception as e:
                print(f"配置保存失败: {e}")
                return False
        
        # 1. 初始化配置
        default_config = init_config()
        print("1. 初始化配置完成")
        
        # 2. 读取并验证默认配置
        read_default = read_config()
        print(f"2. 读取默认配置: {read_default is not None}")
        
        # 3. 更新配置（模拟用户保存）
        test_config = default_config.copy()
        test_config["TencentCloud"] = {"SecretId": "test_id", "SecretKey": "test_key"}
        test_config["EdgeOne"]["ZoneId"] = ["test_zone_id"]
        test_config["Interval"] = 10
        write_result = write_config(test_config)
        print(f"3. 写入测试配置: {write_result}")
        
        # 4. 重新读取配置验证持久化
        reloaded_config = read_config()
        print(f"4. 重新读取配置: {reloaded_config is not None}")
        
        # 5. 验证配置是否正确保存
        config_verified = (
            reloaded_config["TencentCloud"]["SecretId"] == "test_id" and
            reloaded_config["TencentCloud"]["SecretKey"] == "test_key" and
            reloaded_config["EdgeOne"]["ZoneId"] == ["test_zone_id"] and
            reloaded_config["Interval"] == 10
        )
        print(f"5. 配置验证结果: {config_verified}")
        
        # 6. 显示配置文件内容
        print("\n配置文件内容:")
        with open(os.environ['CONFIG_PATH'], 'r', encoding='utf-8') as f:
            print(f.read())
        
        return config_verified
        
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir)
        print("\n测试完成，临时目录已清理")

if __name__ == "__main__":
    print("开始测试配置持久化功能...\n")
    success = test_config_persistence()
    print(f"\n配置持久化测试 {'成功' if success else '失败'}")
