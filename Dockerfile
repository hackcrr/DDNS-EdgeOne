# 基础镜像
FROM python:alpine3.20

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt ./

# 更换为USTC镜像源
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories

# 安装系统依赖
RUN apk update && \
    apk add --no-cache \
    gcc \
    python3-dev \
    musl-dev \
    linux-headers \
    py3-psutil

# 配置时区
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

# 设置 pip 使用USTC镜像源
RUN pip config set global.index-url https://mirrors.ustc.edu.cn/pypi/simple

# 安装依赖
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY src ./src
COPY README.md ./
COPY img.png ./

# 创建配置目录
RUN mkdir -p /app/config

# 设置配置目录为挂载点
VOLUME ["/app/config"]

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH="/app/config/eodo.config.yaml"

# 暴露端口
EXPOSE 54321

# 创建初始化配置文件的脚本
RUN echo 'import yaml; import os; config_dir = "/app/config"; if not os.path.exists(config_dir): os.makedirs(config_dir); config_path = os.environ.get("CONFIG_PATH", "/app/config/eodo.config.yaml"); if not os.path.exists(config_path): default_config = {"TencentCloud": {"SecretId": "", "SecretKey": ""}, "EdgeOne": {"ZoneId": []}, "DnsPod": {"Record": []}, "DingTalk": {"Webhook": ""}, "Interval": 5, "SelectIface": "", "IPv6Regex": "", "CustomIPList": []}; with open(config_path, "w") as f: yaml.dump(default_config, f); print(f"Default config file created at {config_path}")' > /app/init_config.py

# 启动命令，先初始化配置文件，再启动应用
CMD ["sh", "-c", "python /app/init_config.py && python src/eodo/app.py -p 54321"]