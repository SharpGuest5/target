import socket
import requests
import concurrent.futures
import time
import re
import ipaddress
from urllib.parse import urlparse
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# 1. 常用子域名字典（包含100多个常见子域名）
# 解释：这是预定义的常见子域名列表，用于快速扫描目标域名的可能子域名
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'blog', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'cdn', 'm', 'dev', 'test', 'admin', 'secure', 'vpn', 'api', 'app',
    'shop', 'store', 'support', 'forum', 'news', 'portal', 'download',
    'dns', 'dns1', 'dns2', 'static', 'media', 'images', 'img', 'search',
    'login', 'signin', 'signup', 'register', 'account', 'billing', 'payment',
    'status', 'monitor', 'analytics', 'stats', 'git', 'svn', 'crm', 'wiki',
    'docs', 'help', 'kb', 'community', 'beta', 'stage', 'demo', 'lab', 'mx',
    'mx1', 'mx2', 'imap', 'smtp', 'pop3', 'relay', 'proxy', 'firewall',
    'router', 'switch', 'gateway', 'wifi', 'wireless', 'voip', 'chat',
    'meet', 'conference', 'share', 'files', 'drive', 'drop', 'sync', 'backup',
    'cloud', 'db', 'database', 'sql', 'nosql', 'redis', 'cache', 'memcache',
    'elastic', 'kibana', 'grafana', 'prometheus', 'jenkins', 'ci', 'cd',
    'build', 'deploy', 'staging', 'prod', 'production', 'uat', 'qa',
    'old', 'new', 'test1', 'test2', 'demo1', 'demo2', 'legacy', 'archive',
    'web', 'web1', 'web2', 'server', 'server1', 'server2', 'mail1', 'mail2',
    'email', 'email1', 'email2', 'mx0', 'mx01', 'mx10', 'mx20', 'ns0', 'ns01',
    'intranet', 'extranet', 'partner', 'client', 'customers', 'support', 'helpdesk',
    'status', 'health', 'monitor', 'logs', 'metrics', 'dashboard', 'report', 'reports'
]


# 2. IP信息查询函数
# 解释：使用ip-api.com的API获取IP地址的详细信息
def get_ip_details(ip_address):
    """查询IP详细信息"""
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'status': 'success',
                'data': data
            }
        return {'status': 'error', 'message': f'API请求失败: {response.status_code}'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


# 3. 子域名解析函数
# 解释：尝试解析单个子域名，返回其IP地址和主机名
def resolve_subdomain(subdomain, domain):
    """解析单个子域名"""
    full_domain = f"{subdomain}.{domain}"
    try:
        # 设置超时时间
        socket.setdefaulttimeout(2)

        # 解析A记录
        ip_address = socket.gethostbyname(full_domain)

        # 获取主机名（反向解析）
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except:
            hostname = ""

        return {
            'subdomain': full_domain,
            'ip': ip_address,
            'hostname': hostname,
            'status': '在线'
        }
    except (socket.gaierror, socket.timeout):
        # 域名解析失败
        return {}
    except Exception as e:
        return {}


# 4. 子域名扫描函数
# 解释：使用多线程并发扫描所有预定义的子域名
def scan_subdomains(domain, max_workers=40):
    """扫描目标域名的子域名"""
    results = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_subdomain, sub, domain): sub for sub in COMMON_SUBDOMAINS}

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result.get('ip'):
                results.append(result)

    duration = time.time() - start_time
    return {
        'domain': domain,
        'subdomains_found': len(results),
        'scan_duration': f"{duration:.2f}秒",
        'results': results
    }


# 5. 域名验证函数
# 解释：验证并清理用户输入的域名，确保格式正确
def validate_domain(domain):
    """验证并清理域名输入"""
    # 提取纯域名（去除协议等）
    parsed = urlparse(domain)
    if parsed.netloc:
        domain = parsed.netloc
    elif parsed.path:
        domain = parsed.path

    # 移除端口号
    if ':' in domain:
        domain = domain.split(':')[0]

    # 移除路径部分
    if '/' in domain:
        domain = domain.split('/')[0]

    # 验证域名格式 - 更宽松的正则
    if not re.match(r"^([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})$", domain, re.IGNORECASE):
        return None

    return domain.lower()


# 6. Flask路由和前端模板
# 解释：定义前端界面和API路由

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>域名检测</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --dark-color: #2c3e50;
            --text-color: #ffffff;
        }

        .header-section {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #1a2a6c, #b21f1f);
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            position: relative; /* 为绝对定位提供参考 */
        }

        .header-content {
            flex: 1; /* 占据剩余空间 */
            text-align: center;
            padding: 0 50px; /* 确保两侧有足够空间 */
        }

        .header-content h1 {
            font-size: 2.2rem;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: 1px;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
        }

        .header-content p {
            font-size: 1.1rem;
            margin: 0;
        }

        .return-button {
            flex-shrink: 0; /* 防止按钮被压缩 */
            z-index: 10;
        }

        /* 扫描状态提示文字样式 */
        .scan-status-text {
            color: #ffcc00 !important; /* 亮黄色 */
            font-weight: bold !important;
            font-size: 1.2rem !important;
            animation: pulse 1.5s infinite;
        }

        /* 系统统计区域样式 */
        .system-stats {
            background: rgba(40, 40, 60, 0.8);
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
            border: 1px solid rgba(100, 100, 150, 0.5);
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3);

            /* 添加Flex布局确保内容居中 */
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .container {
            padding-top: 20px; /* 添加上边距 */
            padding-bottom: 20px; /* 添加下边距 */
            /* 其他样式保持不变 */
        }

        .stats-container {
            display: flex;
            width: 100%;
            max-width: 400px;
        }

        .stat-item {
            text-align: center;
            padding: 10px 20px; /* 增加左右内边距 */
            flex: 1; /* 等分宽度 */
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: #4fd1c5;
            text-shadow: 0 0 8px rgba(79, 209, 197, 0.5);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 1rem;
            font-weight: 600;
            color: #a0aec0;
            letter-spacing: 1px;
        }

        /* 添加扫描用时动画效果 */
        @keyframes pulse-glow {
            0% { text-shadow: 0 0 5px rgba(79, 209, 197, 0.5); }
            50% { text-shadow: 0 0 15px rgba(79, 209, 197, 0.8); }
            100% { text-shadow: 0 0 5px rgba(79, 209, 197, 0.5); }
        }

        .pulse-animation {
            animation: pulse-glow 2s infinite;
        }

        body {
            background: linear-gradient(135deg, #1a2a6c, #b21f1f, #1a2a6c);
            color: #fff;
            min-height: 100vh;
            padding-bottom: 50px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .card {
            background: rgba(0, 0, 0, 0.7);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            margin-bottom: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
        }
        .card-header {
            background: rgba(0, 0, 0, 0.4);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 1.2rem;
            padding: 15px 20px;
            font-weight: 600;
        }
        .form-control, .btn {
            border-radius: 8px;
        }
        .btn-primary {
            background: linear-gradient(to right, var(--primary-color), var(--secondary-color));
            border: none;
            transition: all 0.3s;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .btn-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .btn-outline-info {
            color: var(--primary-color);
            border-color: var(--primary-color);
        }
        .btn-outline-info:hover {
            background: var(--primary-color);
            color: white;
        }
        .result-box {
            background: rgba(30, 30, 46, 0.8);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            max-height: 500px;
            overflow-y: auto;
        }

        .header-section {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #1a2a6c, #b21f1f);
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            margin-top: 10px; /* 添加上边距 */
        }

        .header-section h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: 1px;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
            text-align: center; /* 确保标题居中 */
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-online {
            background-color: var(--secondary-color);
        }
        .status-offline {
            background-color: var(--danger-color);
        }
        .ip-detail-box {
            background: rgba(25, 25, 35, 0.8);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid var(--primary-color);
        }
        .ip-detail-label {
            font-weight: 600;
            color: var(--primary-color);
            min-width: 100px;
            display: inline-block;
        }
        .system-stats {
            background: rgba(0, 0, 0, 0.4);
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
        }
        .scanning-animation {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .progress-bar {
            background-color: var(--primary-color);
        }
        .pulse {
            display: inline-block;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            background: var(--secondary-color);
            box-shadow: 0 0 0 rgba(78, 204, 163, 0.4);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(78, 204, 163, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 15px rgba(78, 204, 163, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(78, 204, 163, 0); }
        }
        .footer {
            text-align: center;
            padding: 20px;
            margin-top: 40px;
            font-size: 0.9rem;
            opacity: 0.7;
        }
        .alert-box {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 400px;
            display: none;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .result-item:hover {
            background-color: rgba(78, 204, 163, 0.1);
            transform: translateY(-2px);
            transition: all 0.3s ease;
        }
        .ip-map {
            height: 200px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            margin-top: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: rgba(255, 255, 255, 0.5);
        }
        .hostname {
            font-size: 0.9rem;
            color: #aaa;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .dark-badge {
            background-color: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .copy-btn {
            cursor: pointer;
            transition: all 0.2s;
        }
        .copy-btn:hover {
            color: var(--primary-color);
            transform: scale(1.1);
        }
        .table-responsive {
            max-height: 400px;
            overflow-y: auto;
        }
        .tooltip-btn {
            cursor: help;
            border-bottom: 1px dashed #aaa;
        }
         .text-white {
            color: white !important;
        }
        .card .form-text {
            color: #bbb !important;
            opacity: 1 !important;
            font-size: 0.9rem;
            margin-top: 5px;
        }

        .form-control {
           color: #fff !important;
           background: rgba(0, 0, 0, 0.3) !important;
           border: 1px solid rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 警告消息框 -->
        <!-- ...（保持不变）... -->

        <!-- 头部区域 - 添加返回按钮 -->
        <div class="header-section">
            <!-- 左侧占位元素保持对称 -->
            <div style="width: 100px; visibility: hidden;"></div>

            <div class="header-content">
                <h1><i class="fas fa-shield-alt"></i> 域名检测</h1>
                <p>高级域名扫描与IP信息查询工具，帮助您识别潜在的安全威胁</p>
            </div>

            <button class="btn btn-primary return-button" onclick="returnToMain()">
                <i class="fas fa-home me-2"></i>返回主菜单
            </button>
        </div>

        <div class="row">
            <!-- 域名扫描模块 -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header text-white bg-dark">
                         <i class="fas fa-search me-2"></i>域名扫描
                    </div>
                    <div class="card-body">
                        <p class="text-white">扫描目标域名的所有子域名，识别潜在的攻击面</p>
                        <div class="mb-3">
                            <label class="form-label text-white fw-bold">目标域名</label>
                            <div class="input-group">
                                <input type="text" class="form-control form-control-lg" id="domainInput" placeholder="example.com">
                                <button class="btn btn-outline-secondary" type="button" onclick="fillExample('domain')">
                                    <i class="fas fa-lightbulb"></i> 示例
                                </button>
                            </div>
                            <div class="form-text">例如：google.com, baidu.com</div>
                        </div>
                        <button class="btn btn-primary w-100 btn-lg mb-3" onclick="startScan()">
                            <i class="fas fa-bolt me-2"></i>开始扫描
                        </button>

                        <div class="scanning-animation" id="scanningAnimation">
                            <div class="progress mb-3" style="height: 8px;">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
                            </div>
                            <div class="pulse"></div>
                            <div class="mt-2 text-white">扫描中，请稍候...</div>
                        </div>

                        <div class="system-stats">
                            <div class="stats-container">
                                <!-- 子域名统计 -->
                                <div class="stat-item">
                                    <div class="stat-value pulse-animation" id="subdomainCount">0</div>
                                    <div class="stat-label">子域名</div>
                                </div>

                                <!-- 扫描用时统计 -->
                                <div class="stat-item">
                                    <div class="stat-value" id="scanTime">0s</div>
                                    <div class="stat-label">扫描用时</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- IP查询模块 -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header text-white bg-dark">
                        <i class="fas fa-map-marker-alt me-2"></i>IP地理位置查询
                    </div>
                    <div class="card-body">
                        <p class="text-white">查询IP地址的详细地理位置和网络信息</p>
                        <div class="mb-3">
                            <label class="form-label text-white fw-bold">IP地址</label>
                            <div class="input-group">
                                <input type="text" class="form-control form-control-lg" id="ipInput" placeholder="8.8.8.8">
                                <button class="btn btn-outline-secondary" type="button" onclick="fillExample('ip')">
                                    <i class="fas fa-lightbulb"></i> 示例
                                </button>
                            </div>
                            <div class="form-text">例如：8.8.8.8, 114.114.114.114</div>
                        </div>
                        <button class="btn btn-primary w-100 btn-lg mb-3" onclick="queryIP()">
                            <i class="fas fa-globe-americas me-2"></i>查询IP信息
                        </button>

                        <div class="ip-detail-box" id="ipDetails" style="display: none;">
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <h5 class="mb-0 text-white fw-bold"><i class="fas fa-info-circle me-2"></i>IP详细信息</h5>
                                <span class="badge bg-primary" id="ip-status">成功</span>
                            </div>

                            <div class="row mt-3">
                                <div class="col-md-6">
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">国家:</span> 
                                        <span id="ip-country" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">地区:</span> 
                                        <span id="ip-region" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">城市:</span> 
                                        <span id="ip-city" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">邮政编码:</span> 
                                        <span id="ip-zip" class="text-white">--</span>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">ISP:</span> 
                                        <span id="ip-isp" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">组织:</span> 
                                        <span id="ip-org" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">AS编号:</span> 
                                        <span id="ip-as" class="text-white">--</span>
                                    </div>
                                    <div class="mb-2 d-flex">
                                        <span class="ip-detail-label">时区:</span> 
                                        <span id="ip-timezone" class="text-white">--</span>
                                    </div>
                                </div>
                            </div>
                            <div class="mt-3">
                                <div class="d-flex">
                                    <span class="ip-detail-label">坐标:</span>
                                    <span id="ip-latlon" class="text-white">--</span>
                                    <span class="ms-2 copy-btn" onclick="copyToClipboard('ip-latlon')">
                                        <i class="fas fa-copy" title="复制坐标"></i>
                                    </span>
                                </div>
                                <div class="ip-map mt-2" id="ipMap">
                                    <i class="fas fa-map-marked-alt me-2"></i>位置地图预览
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 扫描结果区域 -->
        <div class="card mt-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <div>
                    <i class="fas fa-list me-2 text-white"> 扫描结果</i> <span id="resultDomain">--</span>
                </div>
                <div>
                    <span class="badge bg-success me-2 dark-badge" id="onlineCount">在线: 0</span>
                    <span class="badge bg-danger dark-badge" id="offlineCount">离线: 0</span>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>状态</th>
                                <th>子域名</th>
                                <th>IP地址</th>
                                <th>主机名</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody">
                            <tr>
                                <td colspan="5" class="text-center text-white">等待扫描结果...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- 页脚 -->
        <div class="footer">
        </div>
    </div>

    <script>
        // 全局状态
        let scanning = false;

    // 添加返回主菜单函数
        function returnToMain() {
            // 发送消息给主程序
            fetch('/return-to-main', {
                method: 'POST'
            })
            .then(response => {
                if(response.ok) {
                    // 显示提示信息
                    alert('请关闭此窗口返回主菜单');
                }
            })
            .catch(error => {
                console.error('返回主菜单请求失败:', error);
                alert('返回主菜单请求失败，请手动关闭窗口');
            });
        }

        function showAlert(message, isError = true) {
            const alertBox = document.querySelector('.alert-box');
            const alertMessage = document.getElementById('alertMessage');

            alertBox.classList.remove('alert-success', 'alert-danger');
            alertBox.classList.add(isError ? 'alert-danger' : 'alert-success');

            alertMessage.textContent = message;
            alertBox.style.display = 'block';

            // 5秒后自动关闭
            setTimeout(closeAlert, 5006);
        }

        function closeAlert() {
            document.querySelector('.alert-box').style.display = 'none';
        }

        function fillExample(type) {
            if (type === 'domain') {
                document.getElementById('domainInput').value = 'google.com';
            } else if (type === 'ip') {
                document.getElementById('ipInput').value = '8.8.8.8';
            }
        }

        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;

            navigator.clipboard.writeText(text).then(() => {
                showAlert('已复制到剪贴板', false);
            }).catch(err => {
                showAlert('复制失败: ' + err);
            });
        }

        function startScan() {
            if (scanning) {
                showAlert('扫描正在进行中，请稍候');
                return;
            }

            const domain = document.getElementById('domainInput').value;
            if (!domain) {
                showAlert('请输入要扫描的域名');
                return;
            }

            scanning = true;

            // 显示扫描动画
            document.getElementById('scanningAnimation').style.display = 'block';
            document.getElementById('resultDomain').textContent = domain;
            document.getElementById('resultsBody').innerHTML = '<tr><td colspan="5" class="text-center scan-status-text">扫描中，请稍候...</td></tr>';

            // 重置计数器
            document.getElementById('subdomainCount').textContent = '0';
            document.getElementById('scanTime').textContent = '0s';
            document.getElementById('onlineCount').textContent = '在线: 0';
            document.getElementById('offlineCount').textContent = '离线: 0';

            // 发送扫描请求
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain: domain })
            })
            .then(response => response.json())
            .then(data => {
                scanning = false;
                document.getElementById('scanningAnimation').style.display = 'none';

                // 更新统计信息
                document.getElementById('subdomainCount').textContent = data.subdomains_found;
                document.getElementById('scanTime').textContent = data.scan_duration;

                // 移除动画效果
                document.getElementById('subdomainCount').classList.remove('pulse-animation');

                if (data.status === 'error') {
                    showAlert(data.message);
                    return;
                }

                // 更新统计信息
                document.getElementById('subdomainCount').textContent = data.subdomains_found;
                document.getElementById('scanTime').textContent = data.scan_duration;

                // 更新结果表格
                const resultsBody = document.getElementById('resultsBody');
                resultsBody.innerHTML = '';

                if (data.results.length === 0) {
                    resultsBody.innerHTML = '<tr><td colspan="5" class="text-center">未发现子域名</td></tr>';
                    return;
                }

                let onlineCount = 0;
                let offlineCount = 0;

                data.results.forEach(result => {
                    const isOnline = result.status === '在线';
                    if (isOnline) onlineCount++;
                    else offlineCount++;

                    const row = document.createElement('tr');
                    row.className = 'result-item';
                    row.innerHTML = `
                        <td>
                            <span class="status-indicator ${isOnline ? 'status-online' : 'status-offline'}"></span>
                            ${result.status}
                        </td>
                        <td>${result.subdomain}</td>
                        <td>
                            ${result.ip}
                            <span class="copy-btn ms-2" onclick="copyToClipboard('ip-${result.ip}')">
                                <i class="fas fa-copy"></i>
                            </span>
                            <span id="ip-${result.ip}" style="display:none">${result.ip}</span>
                        </td>
                        <td class="hostname" title="${result.hostname || '无主机名'}">
                            ${result.hostname || '--'}
                        </td>
                        <td>
                            <button class="btn btn-sm btn-outline-info" onclick="queryIPFor('${result.ip}')">
                                <i class="fas fa-search me-1"></i>查询IP
                            </button>
                        </td>
                    `;
                    resultsBody.appendChild(row);
                });

                // 更新在线/离线计数
                document.getElementById('onlineCount').textContent = `在线: ${onlineCount}`;
                document.getElementById('offlineCount').textContent = `离线: ${offlineCount}`;

                showAlert(`扫描完成！发现 ${data.subdomains_found} 个子域名`, false);
            })
            .catch(error => {
                scanning = false;
                document.getElementById('scanningAnimation').style.display = 'none';
                console.error('Error:', error);
                showAlert('扫描过程中发生错误: ' + error.message);
            });
        }

        function queryIP() {
            const ip = document.getElementById('ipInput').value;
            if (!ip) {
                showAlert('请输入要查询的IP地址');
                return;
            }

            fetch('/ip-query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'error') {
                    showAlert(data.message);
                    return;
                }

                const details = data.data;
                document.getElementById('ipDetails').style.display = 'block';

                // 更新IP状态
                document.getElementById('ip-status').textContent = details.status || '未知';
                document.getElementById('ip-status').className = 
                    details.status === 'success' ? 'badge bg-success' : 'badge bg-danger';

                // 更新IP详细信息
                document.getElementById('ip-country').textContent = 
                    `${details.country || '--'} (${details.countryCode || '--'})`;
                document.getElementById('ip-region').textContent = details.regionName || '--';
                document.getElementById('ip-city').textContent = details.city || '--';
                document.getElementById('ip-zip').textContent = details.zip || '--';
                document.getElementById('ip-isp').textContent = details.isp || '--';
                document.getElementById('ip-org').textContent = details.org || '--';
                document.getElementById('ip-as').textContent = details.as || '--';
                document.getElementById('ip-timezone').textContent = details.timezone || '--';

                if (details.lat && details.lon) {
                    document.getElementById('ip-latlon').textContent = 
                        `${details.lat}, ${details.lon}`;

                    // 生成高德地图预览链接
                    const mapUrl = `https://uri.amap.com/marker?position=${details.lon},${details.lat}&name=IP位置&callnative=0`;

                    document.getElementById('ipMap').innerHTML = `
                        <a href="${mapUrl}" target="_blank" class="btn btn-primary">
                            <i class="fas fa-map-marked-alt me-2"></i>查看地图
                        </a>
                    `;

                } else {
                    document.getElementById('ip-latlon').textContent = '--';
                    document.getElementById('ipMap').innerHTML = '<i class="fas fa-map-marked-alt me-2"></i>无坐标数据';
                }

                showAlert(`IP查询成功: ${ip}`, false);
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('IP查询过程中发生错误: ' + error.message);
            });
        }

        function queryIPFor(ip) {
            document.getElementById('ipInput').value = ip;
            queryIP();

            // 滚动到IP查询区域
            document.getElementById('ipDetails').scrollIntoView({ behavior: 'smooth' });
        }

        // 初始化线程数显示
        document.getElementById('threadInfo').textContent = 
            document.getElementById('threadCount').textContent;
    </script>
</body>
</html>
"""


# 7. 主页面路由
# 解释：渲染前端HTML模板
@app.route('/')
def index():
    """主页面"""
    return render_template_string(HTML_TEMPLATE)


# 8. 域名扫描API路由
# 解释：处理扫描请求并返回JSON结果
@app.route('/scan', methods=['POST'])
def scan_domain():
    """子域名扫描API"""
    data = request.get_json()
    raw_domain = data.get('domain', '').strip()

    if not raw_domain:
        return jsonify({'status': 'error', 'message': '请输入域名'})

    # 验证并清理域名
    domain = validate_domain(raw_domain)
    if not domain:
        return jsonify({'status': 'error', 'message': '无效的域名格式'})

    # 扫描子域名
    try:
        result = scan_subdomains(domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'扫描失败: {str(e)}'})


# 9. IP查询API路由
# 解释：处理IP查询请求并返回JSON结果
@app.route('/ip-query', methods=['POST'])
def query_ip():
    """IP查询API"""
    data = request.get_json()
    ip_address = data.get('ip', '').strip()

    if not ip_address:
        return jsonify({'status': 'error', 'message': '请输入IP地址'})

    # 验证IP地址格式
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({'status': 'error', 'message': '无效的IP地址格式'})

    # 查询IP信息
    try:
        result = get_ip_details(ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'查询失败: {str(e)}'})


# 添加新的路由处理返回主菜单请求
@app.route('/return-to-main', methods=['POST'])
def return_to_main():
    """处理返回主菜单请求"""
    # 在实际应用中，这里可以添加关闭逻辑
    # 但因为我们是在主程序中控制，这里只需返回成功响应
    return jsonify({"status": "success", "message": "请关闭窗口返回主菜单"})


# 10. 启动Flask应用
# 解释：运行Web服务器（不自动打开浏览器）
if __name__ == '__main__':
    # 启动Flask应用
    app.run(debug=True, port=5006)
