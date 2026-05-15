# 设备借用管理系统

基于 Flask + SQLite 的设备借用管理平台，支持二维码扫码借用/归还，提供管理后台进行设备、部门、用户管理。

## 功能特性

- 📱 **二维码借用**：扫描二维码即可借用设备，无需登录
- 📋 **二维码归还**：扫描二维码即可归还设备
- 🖥️ **管理后台**：数据总览、设备管理、部门管理、用户管理、表单配置
- 🔐 **权限管理**：超级管理员/普通管理员分级权限
- 📊 **数据导出**：支持导出 CSV
- 🐳 **Docker 部署**：一键构建部署

## 技术栈

- **后端**：Python 3.11 + Flask + Gunicorn
- **数据库**：SQLite
- **前端**：HTML + CSS + JavaScript
- **部署**：Docker + docker-compose

## 快速开始

### 本地运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务
python app.py

# 3. 访问
# 前台：http://localhost:5000
# 后台：http://localhost:5000/admin
```

### Docker 部署

```bash
# 1. 修改 docker-compose.yml 中的数据目录路径
# 2. 一键启动
docker-compose up -d --build

# 3. 访问 http://服务器IP:5000
```


## 项目结构

```
├── app.py                 # 主程序（Flask 应用）
├── qrgen.py               # 二维码生成模块
├── requirements.txt        # Python 依赖
├── Dockerfile              # Docker 镜像构建
├── docker-compose.yml      # Docker 编排配置
├── borrow-system.service   # systemd 服务配置
├── deploy.py               # 部署脚本
├── templates/              # HTML 模板
│   ├── admin.html          # 管理后台首页
│   ├── admin_login.html    # 管理员登录
│   ├── admin_system.html   # 系统管理
│   ├── admin_devices.html  # 设备管理
│   ├── admin_departments.html  # 部门管理
│   ├── borrow.html         # 借用页面
│   ├── return.html         # 归还页面
│   ├── qr.html             # 二维码页面
│   └── qr_home.html        # 二维码首页
└── borrow_data/            # 数据目录（运行时生成）
    └── borrow.db           # SQLite 数据库
```

## 默认账号

- 用户名：`admin`
- 密码：`123456`

> ⚠️ 首次登录后请立即修改密码！

## License

MIT
