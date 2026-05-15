#!/usr/bin/env python3
"""
设备借用系统 - 远程部署脚本
通过 SSH 上传文件到 NAS，构建并启动 Docker 容器
"""

import paramiko
import tarfile
import io
import os
import sys

NAS_HOST = '10.20.1.100'
NAS_PORT = 22026
NAS_USER = 'system'
# [BUG修复#3] 密码从环境变量读取，不再硬编码
NAS_PASS = os.environ.get('NAS_PASS', '')
if not NAS_PASS:
    print("错误：请设置环境变量 NAS_PASS")
    sys.exit(1)
LOCAL_DIR = '/home/zb/.openclaw/workspace/borrow_system'
CONTAINER_NAME = 'borrow-system'

def deploy():
    print(f"[1/6] 连接 NAS {NAS_HOST}:{NAS_PORT}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(NAS_HOST, port=NAS_PORT, username=NAS_USER, password=NAS_PASS, timeout=15)

    # 上传 tar 包
    print("[2/6] 打包并上传源码...")
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
        for root, dirs, files in os.walk(LOCAL_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, os.path.dirname(LOCAL_DIR))
                tar.add(file_path, arcname=arcname)
    tar_buffer.seek(0)

    sftp = ssh.open_sftp()
    sftp.putfo(tar_buffer, '/tmp/borrow_system.tar.gz')
    print("    上传完成")

    # 远程解压
    print("[3/6] 远程解压...")
    stdin, stdout, stderr = ssh.exec_command('cd /tmp && tar -xzf borrow_system.tar.gz && ls borrow_system/')
    print(f"    文件列表: {stdout.read().decode().strip()}")

    # 构建 Docker 镜像
    print("[4/6] 构建 Docker 镜像...")
    stdin, stdout, stderr = ssh.exec_command('cd /tmp/borrow_system && docker build -t borrow-system . 2>&1')
    out = stdout.read().decode()
    err = stderr.read().decode()
    if err and 'error' in err.lower():
        print(f"    构建警告: {err[:500]}")
    print(f"    构建完成: {out[:200]}")

    # 停止旧容器（如果存在）
    print("[5/6] 停止旧容器（如有）...")
    stdin, stdout, stderr = ssh.exec_command(f'docker stop {CONTAINER_NAME} 2>/dev/null; docker rm {CONTAINER_NAME} 2>/dev/null; echo "cleaned"')
    stdout.read()

    # 启动新容器
    print("[6/6] 启动容器...")
    cmd = (
        f'docker run -d --name {CONTAINER_NAME} '
        f'-p 5000:5000 '
        f'-v /tmp/borrow_data:/tmp/borrow_data '
        f'--restart=always '
        f'borrow-system'
    )
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(f"    容器ID: {out.strip()[:12]}")

    # 验证
    stdin, stdout, stderr = ssh.exec_command('curl -s http://localhost:5000/admin | head -5')
    result = stdout.read().decode()
    if '<html' in result:
        print("\n✅ 部署成功！")
        print(f"   管理后台: http://10.20.1.100:5000/admin")
        print(f"   借用表单: http://10.20.1.100:5000/borrow")
        print(f"   归还表单: http://10.20.1.100:5000/return")
    else:
        print(f"\n⚠️ 容器已启动，验证: {result[:100]}")

    # 清理
    stdin, stdout, stderr = ssh.exec_command('rm -f /tmp/borrow_system.tar.gz')
    ssh.close()
    print("\n🚀 完成！")

if __name__ == '__main__':
    deploy()
