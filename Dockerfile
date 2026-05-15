FROM python:3.11-slim

WORKDIR /app

# 安装依赖（国内镜像）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制应用代码（只复制 app.py 和 templates，不复制 __pycache__ 等）
COPY app.py .
COPY qrgen.py .
COPY templates/ ./templates/

# 数据目录（挂载点，不写死进镜像）
RUN mkdir -p /app/data

EXPOSE 5000

# Gunicorn 生产级服务器
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
