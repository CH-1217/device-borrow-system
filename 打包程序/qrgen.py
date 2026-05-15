"""
QR码生成接口
"""
import qrcode
import io
import zipfile
import os
import socket


def get_local_ip():
    """自动获取本机IP地址"""
    try:
        # 连接到一个外部IP来获取本机网络接口的IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_qr_base_url():
    """获取二维码基础 URL，优先从环境变量读取"""
    return os.environ.get('QR_BASE_URL', f'http://{get_local_ip()}:5000')


def generate_qr_png(url, filename=None):
    """通用的QR码生成函数"""
    qr = qrcode.QRCode(
        version=3,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    return img_buffer.getvalue()


def generate_home_qr_png(base_url=None):
    """生成系统首页二维码"""
    if base_url is None:
        base_url = get_qr_base_url()
    return generate_qr_png(base_url)


def generate_borrow_qr_png(base_url=None):
    """生成借用登记二维码"""
    if base_url is None:
        base_url = get_qr_base_url()
    return generate_qr_png(f'{base_url}/borrow')


def generate_return_qr_png(base_url=None):
    """生成归还登记二维码"""
    if base_url is None:
        base_url = get_qr_base_url()
    return generate_qr_png(f'{base_url}/return')


def generate_single_qr_png(base_url=None):
    """生成设备专用二维码（扫码后直接跳转到该设备借用页面）"""
    if base_url is None:
        base_url = get_qr_base_url()
    return generate_qr_png(f'{base_url}/qr')


def generate_device_qr_png(device_id, device_name='', base_url=None):
    """生成指定设备的二维码"""
    if base_url is None:
        base_url = get_qr_base_url()
    return generate_qr_png(f'{base_url}/qr/{device_id}')


def generate_qr_zip(device_ids, device_names, base_url=None):
    """生成设备二维码ZIP包"""
    if base_url is None:
        base_url = get_qr_base_url()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for dev_id in device_ids:
            png_data = generate_device_qr_png(dev_id, device_names.get(dev_id, ''), base_url)
            filename = f'{dev_id}.png'
            zf.writestr(filename, png_data)
    zip_buffer.seek(0)
    return zip_buffer.getvalue()
