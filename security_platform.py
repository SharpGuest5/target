import os
import sys
import subprocess
import threading
import time
import webbrowser
from flask import Flask, send_from_directory

# 服务配置
SERVICES = [
    {"name": "代码审计", "port": 5001, "file": "CodeAudit.py", "cmd": ["python", "CodeAudit.py"]},
    {"name": "数据捕获", "port": 5002, "file": "DataCapture.py", "cmd": ["python", "DataCapture.py"]},
    {"name": "端口扫描", "port": 5003, "file": "PortScanner.py", "cmd": ["python", "PortScanner.py"]},
    {"name": "漏洞扫描", "port": 5004, "file": "VulnerabilityScanner.py", "cmd": ["python", "VulnerabilityScanner.py"]},
    {"name": "态势感知", "port": 5005, "file": "SituationAwareness.py", "cmd": ["python", "SituationAwareness.py"]},
    {"name": "域名检测", "port": 5006, "file": "DomainDetection.py", "cmd": ["python", "DomainDetection.py"]}
]

# 工具箱网页路径
TOOLBOX_HTML = "toolbox.html"

# 服务进程存储
service_processes = {}


def start_service(service):
    """启动单个服务"""
    try:
        print(f"正在启动 {service['name']} 服务 (端口: {service['port']})...")
        process = subprocess.Popen(service["cmd"])
        service_processes[service["port"]] = process
        print(f"✓ {service['name']} 服务已启动 (PID: {process.pid})")
        return True
    except Exception as e:
        print(f"✗ 启动 {service['name']} 服务失败: {str(e)}")
        return False


def stop_service(port):
    """停止单个服务"""
    if port in service_processes:
        print(f"正在停止端口 {port} 的服务...")
        try:
            service_processes[port].terminate()
            service_processes[port].wait(timeout=5)
            print(f"✓ 端口 {port} 的服务已停止")
            return True
        except Exception as e:
            print(f"✗ 停止端口 {port} 的服务失败: {str(e)}")
            return False
    return False


def start_all_services():
    """启动所有服务"""
    print("\n" + "=" * 50)
    print("正在启动所有安全服务...")
    print("=" * 50)

    success_count = 0
    threads = []

    # 使用线程并行启动服务
    def start_service_thread(service):
        if start_service(service):
            nonlocal success_count
            success_count += 1

    for service in SERVICES:
        t = threading.Thread(target=start_service_thread, args=(service,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n" + "=" * 50)
    print(f"服务启动完成: {success_count}/{len(SERVICES)} 个服务已启动")
    print("=" * 50 + "\n")

    return success_count == len(SERVICES)


def stop_all_services():
    """停止所有服务"""
    print("\n" + "=" * 50)
    print("正在停止所有安全服务...")
    print("=" * 50)

    success_count = 0
    for port in list(service_processes.keys()):
        if stop_service(port):
            del service_processes[port]
            success_count += 1

    print("\n" + "=" * 50)
    print(f"服务停止完成: {success_count} 个服务已停止")
    print("=" * 50 + "\n")


def is_port_available(port):
    """检查端口是否可用"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) != 0


def check_service_status():
    """检查服务状态"""
    status = {}
    for service in SERVICES:
        port = service["port"]
        status[port] = {
            "name": service["name"],
            "running": port in service_processes,
            "port_available": not is_port_available(port)
        }
    return status


def create_toolbox_html():
    """创建工具箱网页"""
    html_content = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络安全工具箱</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
        }

        body {
            background: linear-gradient(135deg, #0c1a25, #152535, #1c2e42);
            color: #e0f7fa;
            min-height: 100vh;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        header {
            text-align: center;
            margin: 20px 0 30px;
            width: 100%;
            max-width: 1000px;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .logo i {
            font-size: 2.5rem;
            color: #4fc3f7;
        }

        h1 {
            font-size: 2.5rem;
            background: linear-gradient(to right, #4fc3f7, #29b6f6, #039be5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            text-shadow: 0 2px 8px rgba(0, 150, 255, 0.3);
        }

        .subtitle {
            font-size: 1.1rem;
            color: #b3e5fc;
            max-width: 600px;
            margin: 0 auto;
            line-height: 1.6;
        }

        .container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            width: 100%;
            max-width: 1000px;
            margin-bottom: 30px;
        }

        .tool-card {
            background: rgba(25, 45, 65, 0.7);
            border-radius: 10px;
            overflow: hidden;
            transition: all 0.3s ease;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(64, 164, 223, 0.3);
            display: flex;
            flex-direction: column;
            height: 100%;
        }

        .tool-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 150, 255, 0.25);
            border-color: rgba(64, 164, 223, 0.6);
            background: rgba(30, 55, 80, 0.8);
        }

        .card-header {
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 12px;
            background: rgba(20, 35, 55, 0.6);
            border-bottom: 1px solid rgba(64, 164, 223, 0.3);
        }

        .card-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #01579b, #0288d1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .card-port {
            background: rgba(3, 155, 229, 0.2);
            padding: 2px 8px;
            border-radius: 15px;
            font-size: 0.85rem;
            font-weight: 500;
            margin-top: 3px;
        }

        .card-content {
            padding: 15px;
            flex-grow: 1;
        }

        .card-content p {
            color: #b3e5fc;
            line-height: 1.5;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }

        .card-footer {
            padding: 12px 15px;
            background: rgba(20, 35, 55, 0.6);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .service-status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
        }

        .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .status-online {
            background-color: #4caf50;
            box-shadow: 0 0 6px #4caf50;
        }

        .status-offline {
            background-color: #f44336;
            box-shadow: 0 0 6px #f44336;
        }

        .status-starting {
            background-color: #ffc107;
            box-shadow: 0 0 6px #ffc107;
            animation: pulse 1.5s infinite;
        }

        .launch-btn {
            background: linear-gradient(to right, #0288d1, #039be5);
            color: white;
            border: none;
            padding: 6px 16px;
            border-radius: 25px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.9rem;
        }

        .launch-btn:hover {
            background: linear-gradient(to right, #039be5, #03a9f4);
            box-shadow: 0 0 10px rgba(3, 155, 229, 0.5);
            transform: scale(1.05);
        }

        .launch-btn i {
            font-size: 0.8rem;
        }

        .launch-btn:disabled {
            background: #607d8b;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        footer {
            text-align: center;
            padding: 15px;
            color: #81d4fa;
            font-size: 0.85rem;
            margin-top: auto;
            width: 100%;
            max-width: 1000px;
            border-top: 1px solid rgba(64, 164, 223, 0.2);
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }

        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }

            h1 {
                font-size: 2rem;
            }

            .subtitle {
                font-size: 1rem;
            }
        }

        .action-bar {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            max-width: 1000px;
            width: 100%;
        }

        .action-btn {
            flex: 1;
            padding: 10px 0;
            text-align: center;
            border-radius: 8px;
            background: rgba(3, 155, 229, 0.3);
            color: #b3e5fc;
            cursor: pointer;
            transition: all 0.3s;
            border: none;
            font-size: 0.95rem;
            font-weight: 500;
        }

        .action-btn:hover {
            background: rgba(3, 155, 229, 0.5);
        }

        .action-btn.primary {
            background: linear-gradient(to right, #0288d1, #039be5);
            color: white;
        }

        .action-btn.primary:hover {
            background: linear-gradient(to right, #039be5, #03a9f4);
        }

        .console {
            background: rgba(15, 30, 45, 0.8);
            border-radius: 10px;
            padding: 15px;
            width: 100%;
            max-width: 1000px;
            margin-bottom: 20px;
            font-family: monospace;
            font-size: 0.9rem;
            max-height: 200px;
            overflow-y: auto;
        }

        .console-line {
            margin-bottom: 5px;
            line-height: 1.4;
        }

        .console-line.info {
            color: #4fc3f7;
        }

        .console-line.success {
            color: #8bc34a;
        }

        .console-line.warning {
            color: #ffc107;
        }

        .console-line.error {
            color: #f44336;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-shield-alt"></i>
            <div>
                <h1>网络安全工具箱</h1>
                <p class="subtitle">安全服务已启动 - 点击访问工具</p>
            </div>
        </div>
    </header>

    <div class="console" id="console">
        <div class="console-line info">[系统] 正在启动安全服务...</div>
        <div class="console-line">[状态] 初始化工具箱控制台</div>
    </div>

    <div class="action-bar">
        <button class="action-btn primary" id="start-all-btn">
            <i class="fas fa-play-circle"></i> 启动所有服务
        </button>
        <button class="action-btn" id="stop-all-btn">
            <i class="fas fa-stop-circle"></i> 停止所有服务
        </button>
    </div>

    <div class="container">
        <!-- 代码审计 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-code"></i>
                </div>
                <div>
                    <div class="card-title">代码审计</div>
                    <div class="card-port">端口: 5001</div>
                </div>
            </div>
            <div class="card-content">
                <p>对应用程序源代码进行安全审查，识别潜在安全漏洞。</p>
                <p><i class="fas fa-file-code"></i> 文件: CodeAudit.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5001"></div>
                    <span id="status-text-5001">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5001">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>

        <!-- 数据捕获 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-database"></i>
                </div>
                <div>
                    <div class="card-title">数据捕获</div>
                    <div class="card-port">端口: 5002</div>
                </div>
            </div>
            <div class="card-content">
                <p>监控网络流量，分析数据传输内容。</p>
                <p><i class="fas fa-file-code"></i> 文件: DataCapture.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5002"></div>
                    <span id="status-text-5002">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5002">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>

        <!-- 端口扫描 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-plug"></i>
                </div>
                <div>
                    <div class="card-title">端口扫描</div>
                    <div class="card-port">端口: 5003</div>
                </div>
            </div>
            <div class="card-content">
                <p>扫描目标系统的开放端口和服务。</p>
                <p><i class="fas fa-file-code"></i> 文件: PortScanner.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5003"></div>
                    <span id="status-text-5003">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5003">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>

        <!-- 漏洞扫描 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-bug"></i>
                </div>
                <div>
                    <div class="card-title">漏洞扫描</div>
                    <div class="card-port">端口: 5004</div>
                </div>
            </div>
            <div class="card-content">
                <p>扫描系统和应用程序中的已知漏洞。</p>
                <p><i class="fas fa-file-code"></i> 文件: VulnerabilityScanner.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5004"></div>
                    <span id="status-text-5004">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5004">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>

        <!-- 态势感知 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-chart-network"></i>
                </div>
                <div>
                    <div class="card-title">态势感知</div>
                    <div class="card-port">端口: 5005</div>
                </div>
            </div>
            <div class="card-content">
                <p>实时监控网络安全态势，可视化威胁情报。</p>
                <p><i class="fas fa-file-code"></i> 文件: SituationAwareness.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5005"></div>
                    <span id="status-text-5005">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5005">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>

        <!-- 域名检测 -->
        <div class="tool-card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-globe"></i>
                </div>
                <div>
                    <div class="card-title">域名检测</div>
                    <div class="card-port">端口: 5006</div>
                </div>
            </div>
            <div class="card-content">
                <p>分析域名的安全状况，包括DNS配置和SSL证书。</p>
                <p><i class="fas fa-file-code"></i> 文件: DomainDetection.py</p>
            </div>
            <div class="card-footer">
                <div class="service-status">
                    <div class="status-indicator status-offline" id="status-5006"></div>
                    <span id="status-text-5006">未运行</span>
                </div>
                <button class="launch-btn" id="btn-5006">
                    <i class="fas fa-play"></i> 启动
                </button>
            </div>
        </div>
    </div>

    <footer>
        <p>网络安全工具箱 &copy; 2025 | 双击启动服务，点击"访问"打开工具</p>
    </footer>

    <script>
        // 服务端口与文件的映射
        const serviceMap = {
            5001: { name: "代码审计", file: "CodeAudit.py" },
            5002: { name: "数据捕获", file: "DataCapture.py" },
            5003: { name: "端口扫描", file: "PortScanner.py" },
            5004: { name: "漏洞扫描", file: "VulnerabilityScanner.py" },
            5005: { name: "态势感知", file: "SituationAwareness.py" },
            5006: { name: "域名检测", file: "DomainDetection.py" }
        };

        // 控制台元素
        const consoleElement = document.getElementById('console');

        // 添加控制台输出
        function addConsoleOutput(message, type = '') {
            const line = document.createElement('div');
            line.className = `console-line ${type}`;
            line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            consoleElement.appendChild(line);
            consoleElement.scrollTop = consoleElement.scrollHeight;
        }

        // 更新服务状态
        function updateServiceStatus(port, status) {
            const statusElem = document.getElementById(`status-${port}`);
            const textElem = document.getElementById(`status-text-${port}`);
            const buttonElem = document.getElementById(`btn-${port}`);

            if (status === 'running') {
                statusElem.className = "status-indicator status-online";
                textElem.textContent = "运行中";
                buttonElem.innerHTML = '<i class="fas fa-external-link-alt"></i> 访问';
                buttonElem.onclick = () => {
                    window.open(`http://127.0.0.1:${port}`, '_blank');
                };
            } else if (status === 'starting') {
                statusElem.className = "status-indicator status-starting";
                textElem.textContent = "启动中...";
                buttonElem.disabled = true;
            } else {
                statusElem.className = "status-indicator status-offline";
                textElem.textContent = "未运行";
                buttonElem.innerHTML = '<i class="fas fa-play"></i> 启动';
                buttonElem.onclick = () => startService(port);
                buttonElem.disabled = false;
            }
        }

        // 启动单个服务
        function startService(port) {
            const service = serviceMap[port];
            if (!service) return;

            addConsoleOutput(`正在启动 ${service.name} 服务...`, "info");
            updateServiceStatus(port, 'starting');

            fetch(`/start/${port}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleOutput(`${service.name} 服务已启动`, "success");
                        updateServiceStatus(port, 'running');
                    } else {
                        addConsoleOutput(`启动 ${service.name} 服务失败: ${data.message}`, "error");
                        updateServiceStatus(port, 'stopped');
                    }
                })
                .catch(error => {
                    addConsoleOutput(`启动 ${service.name} 服务时出错: ${error}`, "error");
                    updateServiceStatus(port, 'stopped');
                });
        }

        // 停止单个服务
        function stopService(port) {
            const service = serviceMap[port];
            if (!service) return;

            addConsoleOutput(`正在停止 ${service.name} 服务...`, "info");
            updateServiceStatus(port, 'starting');

            fetch(`/stop/${port}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleOutput(`${service.name} 服务已停止`, "warning");
                        updateServiceStatus(port, 'stopped');
                    } else {
                        addConsoleOutput(`停止 ${service.name} 服务失败: ${data.message}`, "error");
                        updateServiceStatus(port, 'running');
                    }
                })
                .catch(error => {
                    addConsoleOutput(`停止 ${service.name} 服务时出错: ${error}`, "error");
                });
        }

        // 启动所有服务
        function startAllServices() {
            addConsoleOutput("正在启动所有安全服务...", "info");
            fetch('/start_all')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleOutput("所有服务已成功启动", "success");
                        // 更新所有服务状态
                        for (const port in serviceMap) {
                            updateServiceStatus(parseInt(port), 'running');
                        }
                    } else {
                        addConsoleOutput(`启动所有服务失败: ${data.message}`, "error");
                    }
                })
                .catch(error => {
                    addConsoleOutput(`启动所有服务时出错: ${error}`, "error");
                });
        }

        // 停止所有服务
        function stopAllServices() {
            addConsoleOutput("正在停止所有安全服务...", "info");
            fetch('/stop_all')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addConsoleOutput("所有服务已成功停止", "warning");
                        // 更新所有服务状态
                        for (const port in serviceMap) {
                            updateServiceStatus(parseInt(port), 'stopped');
                        }
                    } else {
                        addConsoleOutput(`停止所有服务失败: ${data.message}`, "error");
                    }
                })
                .catch(error => {
                    addConsoleOutput(`停止所有服务时出错: ${error}`, "error");
                });
        }

        // 初始化服务状态
        function initServiceStatus() {
            fetch('/status')
                .then(response => response.json())
                .then(data => {
                    for (const port in data) {
                        if (data[port].running) {
                            updateServiceStatus(parseInt(port), 'running');
                            addConsoleOutput(`${data[port].name} 服务正在运行`, "success");
                        } else {
                            updateServiceStatus(parseInt(port), 'stopped');
                        }
                    }
                })
                .catch(error => {
                    addConsoleOutput(`获取服务状态失败: ${error}`, "error");
                });
        }

        // 初始化按钮事件
        document.addEventListener('DOMContentLoaded', () => {
            // 添加初始控制台消息
            addConsoleOutput("工具箱已加载，正在检查服务状态...", "info");

            // 设置按钮事件
            document.getElementById('start-all-btn').addEventListener('click', startAllServices);
            document.getElementById('stop-all-btn').addEventListener('click', stopAllServices);

            // 初始化服务按钮事件
            for (const port in serviceMap) {
                const portNum = parseInt(port);
                document.getElementById(`btn-${port}`).onclick = () => startService(portNum);
            }

            // 初始化服务状态
            setTimeout(initServiceStatus, 500);
        });
    </script>
</body>
</html>
    """
    with open(TOOLBOX_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"工具箱网页已创建: {TOOLBOX_HTML}")


def run_toolbox_server():
    """运行工具箱网页服务器"""
    app = Flask(__name__)

    @app.route('/')
    def index():
        return send_from_directory('.', TOOLBOX_HTML)

    @app.route('/start_all', methods=['POST'])
    def start_all():
        success = start_all_services()
        return {"success": success, "message": "所有服务已启动" if success else "启动服务失败"}

    @app.route('/stop_all', methods=['POST'])
    def stop_all():
        stop_all_services()
        return {"success": True, "message": "所有服务已停止"}

    @app.route('/start/<int:port>', methods=['POST'])
    def start_service_route(port):
        service = next((s for s in SERVICES if s["port"] == port), None)
        if service:
            success = start_service(service)
            return {"success": success,
                    "message": f"{service['name']}服务已启动" if success else f"启动{service['name']}服务失败"}
        return {"success": False, "message": f"找不到端口{port}的服务"}

    @app.route('/stop/<int:port>', methods=['POST'])
    def stop_service_route(port):
        success = stop_service(port)
        return {"success": success, "message": f"端口{port}的服务已停止" if success else f"停止端口{port}的服务失败"}

    @app.route('/status')
    def status():
        return check_service_status()

    print("启动工具箱网页服务器...")
    threading.Thread(target=app.run, kwargs={'port': 8000}, daemon=True).start()


def main():
    """主函数"""
    print("=" * 50)
    print("网络安全工具箱启动器")
    print("=" * 50)

    # 创建工具箱网页
    if not os.path.exists(TOOLBOX_HTML):
        create_toolbox_html()

    # 启动工具箱网页服务器
    run_toolbox_server()

    # 启动所有服务
    start_all_services()

    # 打开浏览器
    print("\n在浏览器中打开工具箱...")
    time.sleep(1)
    webbrowser.open('http://localhost:8000')

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止所有服务...")
        stop_all_services()
        print("工具箱已关闭")


if __name__ == "__main__":
    main()
