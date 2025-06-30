import nmap
import os
import time
import logging
import platform
import threading
from flask import Flask, render_template_string, request, jsonify
from typing import List, Dict, Any, Tuple, Optional

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('NmapScanner')

# 初始化 Flask 应用
app = Flask(__name__)
app.secret_key = 'your_secret_key'


class NmapScanner:
    def __init__(self):
        """初始化 Nmap 扫描器"""
        # 尝试自动定位 Nmap
        self.nm = self.find_nmap_scanner()
        self.scan_results = {}
        self.scan_progress = {}
        self.scan_start_time = 0
        self.current_scan_id = None
        self.is_windows = platform.system() == "Windows"

    def find_nmap_scanner(self):
        """尝试找到可用的 Nmap 可执行文件"""
        # 尝试默认位置
        try:
            return nmap.PortScanner()
        except nmap.PortScannerError:
            pass

        # 常见 Windows 安装路径
        windows_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Nmap\nmap.exe"
        ]

        # 常见 Linux/macOS 路径
        unix_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/local/bin/nmap"
        ]

        # 检查所有可能的路径
        all_paths = windows_paths + unix_paths
        for path in all_paths:
            if os.path.exists(path):
                try:
                    return nmap.PortScanner(nmap_search_path=(path,))
                except:
                    continue

        # 如果都失败，抛出异常
        raise EnvironmentError("无法找到 Nmap 可执行文件。请确保已安装 Nmap 并添加到系统 PATH")

    def scan(self, targets: str, ports: str = '1-1024',
             arguments: str = '-sS -T4', scan_id: str = None) -> str:
        """
        执行 Nmap 扫描

        参数:
            targets: 扫描目标 (IP, 主机名或 CIDR 范围)
            ports: 端口范围 (默认: 1-1024)
            arguments: Nmap 参数 (默认: '-sS -T4' SYN 扫描)
            scan_id: 可选扫描ID用于跟踪进度

        返回:
            扫描ID
        """
        if scan_id is None:
            scan_id = f"scan_{int(time.time())}"

        self.current_scan_id = scan_id
        self.scan_start_time = time.time()
        self.scan_progress[scan_id] = {
            'status': 'running',
            'start_time': self.scan_start_time,
            'targets': targets,
            'progress': '0%'
        }

        logger.info(f"开始扫描 {scan_id}: 目标={targets}, 端口={ports}, 参数={arguments}")

        try:
            # Windows 系统不使用 sudo 参数
            if self.is_windows:
                logger.debug("Windows 系统，不使用 sudo 参数")
                self.nm.scan(hosts=targets, ports=ports, arguments=arguments)
            else:
                logger.debug("类 Unix 系统，使用 sudo 参数")
                self.nm.scan(hosts=targets, ports=ports, arguments=arguments, sudo=True)

            # 存储扫描结果
            self.scan_results[scan_id] = {
                'scan_data': self.nm._scan_result,
                'scan_time': time.time() - self.scan_start_time
            }

            self.scan_progress[scan_id]['status'] = 'completed'
            self.scan_progress[scan_id]['end_time'] = time.time()

            logger.info(f"扫描 {scan_id} 完成! 耗时 {self.scan_results[scan_id]['scan_time']:.2f} 秒")

        except nmap.PortScannerError as e:
            self.scan_progress[scan_id]['status'] = 'error'
            self.scan_progress[scan_id]['error'] = str(e)
            logger.error(f"扫描 {scan_id} 出错: {e}")
        except Exception as e:
            self.scan_progress[scan_id]['status'] = 'error'
            self.scan_progress[scan_id]['error'] = str(e)
            logger.exception(f"扫描 {scan_id} 发生异常")

        return scan_id

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """
        获取扫描进度信息

        参数:
            scan_id: 扫描ID

        返回:
            包含进度信息的字典
        """
        if scan_id not in self.scan_progress:
            return {'status': 'not_found'}

        # 如果扫描正在进行中，尝试获取进度
        if self.scan_progress[scan_id]['status'] == 'running':
            try:
                # 更新进度信息
                scan_info = self.nm._nm.get_scan_progress()
                if scan_info:
                    self.scan_progress[scan_id]['progress'] = scan_info[0]
                    self.scan_progress[scan_id]['remaining'] = scan_info[1]
                    self.scan_progress[scan_id]['eta'] = scan_info[2]
            except:
                pass

        return self.scan_progress[scan_id]

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        获取扫描结果

        参数:
            scan_id: 扫描ID

        返回:
            包含扫描结果的字典
        """
        if scan_id not in self.scan_results:
            return {'error': 'Scan not found or not completed'}

        # 如果扫描还在进行中，等待完成
        while self.scan_progress.get(scan_id, {}).get('status') == 'running':
            time.sleep(0.5)

        if self.scan_progress.get(scan_id, {}).get('status') != 'completed':
            return {'error': 'Scan did not complete successfully'}

        return self.parse_results(self.scan_results[scan_id]['scan_data'])

    def parse_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析 Nmap 扫描结果

        参数:
            scan_data: Nmap 原始扫描数据

        返回:
            结构化的扫描结果
        """
        results = {
            'command': scan_data.get('nmap', {}).get('command_line', ''),
            'version': scan_data.get('nmap', {}).get('version', ''),
            'scan_time': scan_data.get('nmap', {}).get('scanstats', {}).get('elapsed', '0'),
            'hosts': []
        }

        for host in scan_data.get('scan', {}).values():
            host_info = {
                'ip': host['addresses'].get('ipv4', host['addresses'].get('ipv6', '')),
                'mac': host['addresses'].get('mac', ''),
                'hostnames': host.get('hostnames', []),
                'status': host['status']['state'],
                'reason': host['status']['reason'],
                'os': {},
                'ports': []
            }

            # 解析操作系统信息
            if 'osmatch' in host:
                for osmatch in host['osmatch']:
                    host_info['os'] = {
                        'name': osmatch['name'],
                        'accuracy': osmatch['accuracy'],
                        'osclass': osmatch.get('osclass', [])
                    }
                    break  # 只取最可能的结果

            # 解析端口信息
            for proto in ['tcp', 'udp']:
                if proto in host:
                    for port, port_info in host[proto].items():
                        service = port_info.get('product', '')
                        if port_info.get('version'):
                            service += f" {port_info['version']}"
                        if port_info.get('extrainfo'):
                            service += f" ({port_info['extrainfo']})"

                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': service,
                            'reason': port_info['reason'],
                            'cpe': port_info.get('cpe', '')
                        })

            # 按端口号排序
            host_info['ports'] = sorted(host_info['ports'], key=lambda x: x['port'])
            results['hosts'].append(host_info)

        return results

    def get_scan_summary(self, scan_id: str) -> str:
        """
        获取扫描摘要

        参数:
            scan_id: 扫描ID

        返回:
            扫描摘要文本
        """
        results = self.get_scan_results(scan_id)
        if 'error' in results:
            return f"错误: {results['error']}"

        summary = []
        summary.append(f"扫描命令: {results['command']}")
        summary.append(f"扫描耗时: {results['scan_time']} 秒")
        summary.append(f"发现主机: {len(results['hosts'])}")

        for host in results['hosts']:
            summary.append(f"\n主机: {host['ip']} ({host.get('mac', '无MAC地址')})")
            summary.append(f"状态: {host['status']} ({host['reason']})")

            if host.get('os'):
                summary.append(
                    f"操作系统: {host['os'].get('name', '未知')} ({host['os'].get('accuracy', '0')}% 准确率)")

            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                summary.append("开放端口:")
                for port in open_ports:
                    summary.append(f"  {port['port']}/{port['protocol']}: {port['service']}")
            else:
                summary.append("无开放端口")

        return "\n".join(summary)

    def get_scan_commands(self) -> Dict[str, str]:
        """
        获取常用扫描命令模板

        返回:
            包含常用扫描命令的字典
        """
        return {
            "SYN扫描": "nmap -sS -T4 [目标]",
            "TCP全连接扫描": "nmap -sT -T4 [目标]",
            "UDP扫描": "nmap -sU -T4 [目标]",
            "操作系统检测": "nmap -O [目标]",
            "服务版本检测": "nmap -sV [目标]",
            "全面扫描": "nmap -A [目标]",
            "快速扫描": "nmap -F -T4 [目标]",
            "Ping扫描": "nmap -sn [目标]",
            "安全扫描": "nmap --script safe [目标]",
            "漏洞扫描": "nmap --script vuln [目标]"
        }

    def get_host_details(self, scan_id: str, host_ip: str) -> Optional[Dict[str, Any]]:
        """
        获取特定主机的详细信息

        参数:
            scan_id: 扫描ID
            host_ip: 主机IP地址

        返回:
            主机详细信息字典
        """
        results = self.get_scan_results(scan_id)
        if 'error' in results:
            return None

        for host in results['hosts']:
            if host['ip'] == host_ip:
                return host

        return None

    def stop_scan(self, scan_id: str) -> bool:
        """
        停止正在进行的扫描

        参数:
            scan_id: 扫描ID

        返回:
            是否成功停止
        """
        if scan_id in self.scan_progress and self.scan_progress[scan_id]['status'] == 'running':
            try:
                self.nm.stop()
                self.scan_progress[scan_id]['status'] = 'stopped'
                self.scan_progress[scan_id]['end_time'] = time.time()
                logger.info(f"扫描 {scan_id} 已停止")
                return True
            except:
                logger.error(f"停止扫描 {scan_id} 失败")
                return False
        return False

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        列出所有扫描记录

        返回:
            扫描记录列表
        """
        scans = []
        for scan_id, scan_info in self.scan_progress.items():
            scan_data = {
                'scan_id': scan_id,
                'status': scan_info['status'],
                'targets': scan_info['targets'],
                'start_time': scan_info.get('start_time', 0),
                'end_time': scan_info.get('end_time', 0),
                'duration': scan_info.get('end_time', time.time()) - scan_info.get('start_time', time.time())
            }

            if 'error' in scan_info:
                scan_data['error'] = scan_info['error']

            scans.append(scan_data)

        # 按开始时间倒序排列
        return sorted(scans, key=lambda x: x['start_time'], reverse=True)


# 创建扫描器实例
scanner = NmapScanner()

# 存储当前扫描任务
current_scan_id = None
scan_thread = None


def background_scan(targets, ports, arguments):
    """在后台线程中执行扫描"""
    global current_scan_id
    current_scan_id = scanner.scan(targets, ports, arguments)


# Flask 路由
@app.route('/')
def index():
    """主页面"""
    return render_template_string(HTML_TEMPLATE, scan_commands=scanner.get_scan_commands())


@app.route('/start_scan', methods=['POST'])
def start_scan():
    """开始新的扫描"""
    global scan_thread, current_scan_id

    # 获取表单数据
    targets = request.form.get('targets', '')
    ports = request.form.get('ports', '1-1024')
    scan_type = request.form.get('scan_type', 'custom')
    custom_args = request.form.get('custom_args', '')

    # 确定扫描参数
    if scan_type == 'quick':
        arguments = '-F -T4'  # 快速扫描
    elif scan_type == 'syn':
        arguments = '-sS -T4'  # SYN扫描
    elif scan_type == 'full':
        arguments = '-A -T4'  # 全面扫描
    elif scan_type == 'udp':
        arguments = '-sU -T4'  # UDP扫描
    elif scan_type == 'ping':
        arguments = '-sn'  # Ping扫描
    else:
        arguments = custom_args  # 自定义参数

    # 启动后台扫描线程
    scan_thread = threading.Thread(target=background_scan, args=(targets, ports, arguments))
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({'scan_id': current_scan_id})


@app.route('/scan_progress/<scan_id>')
def scan_progress(scan_id):
    """获取扫描进度"""
    progress = scanner.get_scan_progress(scan_id)
    return jsonify(progress)


@app.route('/scan_results/<scan_id>')
def scan_results(scan_id):
    """获取扫描结果"""
    results = scanner.get_scan_results(scan_id)
    return jsonify(results)


@app.route('/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """停止扫描"""
    success = scanner.stop_scan(scan_id)
    return jsonify({'success': success})


@app.route('/scan_history')
def scan_history():
    """获取扫描历史"""
    scans = scanner.list_scans()
    return jsonify(scans)


@app.route('/host_details/<scan_id>/<host_ip>')
def host_details(scan_id, host_ip):
    """获取主机详情"""
    details = scanner.get_host_details(scan_id, host_ip)
    if details:
        return jsonify(details)
    else:
        return jsonify({'error': 'Host not found'}), 404


# HTML 模板和样式
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap 网页扫描器</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .card {
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .card-header {
            border-top-left-radius: 10px !important;
            border-top-right-radius: 10px !important;
        }

        .progress {
            border-radius: 10px;
            overflow: visible;
        }

        .progress-bar {
            transition: width 1s ease;
        }

        #results-container .card {
            margin-bottom: 15px;
        }

        .badge {
            font-weight: normal;
        }

        #history-table {
            font-size: 0.9rem;
        }

        #history-table th {
            background-color: #f1f1f1;
        }

        footer {
            background-color: #e9ecef;
            border-top: 1px solid #dee2e6;
        }

        .alert {
            border-radius: 8px;
        }

        .table-bordered {
            border-radius: 8px;
            overflow: hidden;
        }

        .btn {
            border-radius: 6px;
            transition: all 0.2s;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <header class="text-center mb-4">
            <h1 class="display-4">Nmap 网页扫描器</h1>
            <p class="lead">在浏览器中执行专业的网络扫描</p>
        </header>

        <!-- 扫描控制面板 -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h2 class="h5 mb-0">扫描控制</h2>
            </div>
            <div class="card-body">
                <form id="scan-form">
                    <div class="mb-3">
                        <label for="targets" class="form-label">扫描目标</label>
                        <input type="text" class="form-control" id="targets" 
                               placeholder="输入IP地址、主机名或网络范围 (如 scanme.nmap.org 或 192.168.1.0/24)" 
                               value="scanme.nmap.org" required>
                        <div class="form-text">多个目标可以用逗号分隔</div>
                    </div>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="ports" class="form-label">端口范围</label>
                            <input type="text" class="form-control" id="ports" 
                                   placeholder="如 1-1024 或 80,443,22" 
                                   value="20-443">
                        </div>

                        <div class="col-md-6 mb-3">
                            <label for="scan-type" class="form-label">扫描类型</label>
                            <select class="form-select" id="scan-type">
                                <option value="quick">快速扫描</option>
                                <option value="syn" selected>SYN扫描</option>
                                <option value="udp">UDP扫描</option>
                                <option value="full">全面扫描</option>
                                <option value="ping">Ping扫描</option>
                                <option value="custom">自定义参数</option>
                            </select>
                        </div>
                    </div>

                    <div class="mb-3" id="custom-args-container" style="display: none;">
                        <label for="custom-args" class="form-label">自定义参数</label>
                        <input type="text" class="form-control" id="custom-args" 
                               placeholder="如 -sS -T4 -O -sV">
                        <div class="form-text">输入Nmap命令行参数</div>
                    </div>

                    <div class="d-grid gap-2 d-md-flex">
                        <button type="button" id="start-scan" class="btn btn-success me-md-2">
                            <i class="bi bi-play-fill"></i> 开始扫描
                        </button>
                        <button type="button" id="stop-scan" class="btn btn-danger" disabled>
                            <i class="bi bi-stop-fill"></i> 停止扫描
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- 进度面板 -->
        <div class="card mb-4" id="progress-section" style="display: none;">
            <div class="card-header bg-info text-white">
                <h2 class="h5 mb-0">扫描进度</h2>
            </div>
            <div class="card-body">
                <div class="progress mb-3" style="height: 25px;">
                    <div id="progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" 
                         role="progressbar" style="width: 0%;">0%</div>
                </div>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">状态</h6>
                                <p id="scan-status" class="card-text">等待开始</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">剩余时间</h6>
                                <p id="remaining-time" class="card-text">未知</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">预计完成</h6>
                                <p id="eta" class="card-text">未知</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 结果面板 -->
        <div class="card mb-4" id="results-section" style="display: none;">
            <div class="card-header bg-success text-white">
                <h2 class="h5 mb-0">扫描结果</h2>
            </div>
            <div class="card-body">
                <div id="results-container">
                    <!-- 结果将通过AJAX加载 -->
                </div>
            </div>
        </div>

        <!-- 历史记录面板 -->
        <div class="card">
            <div class="card-header bg-secondary text-white">
                <h2 class="h5 mb-0">扫描历史</h2>
            </div>
            <div class="card-body">
                <table class="table table-striped" id="history-table">
                    <thead>
                        <tr>
                            <th>扫描ID</th>
                            <th>目标</th>
                            <th>状态</th>
                            <th>开始时间</th>
                            <th>耗时</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- 历史记录将通过AJAX加载 -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <footer class="bg-light py-3 mt-4">
        <div class="container text-center">
            <p class="mb-0">Nmap 网页扫描器 &copy; 2023</p>
        </div>
    </footer>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        // 全局变量
        let currentScanId = null;
        let progressInterval = null;

        // 扫描类型切换
        $('#scan-type').change(function() {
            if ($(this).val() === 'custom') {
                $('#custom-args-container').show();
            } else {
                $('#custom-args-container').hide();
            }
        });

        // 开始扫描
        $('#start-scan').click(function() {
            const targets = $('#targets').val();
            const ports = $('#ports').val();
            const scanType = $('#scan-type').val();
            const customArgs = $('#custom-args').val();

            if (!targets) {
                alert('请输入扫描目标');
                return;
            }

            // 显示进度面板
            $('#progress-section').show();
            $('#results-section').hide();
            $('#stop-scan').prop('disabled', false);
            $(this).prop('disabled', true);

            // 发送扫描请求
            $.post('/start_scan', {
                targets: targets,
                ports: ports,
                scan_type: scanType,
                custom_args: customArgs
            }, function(response) {
                currentScanId = response.scan_id;
                $('#scan-status').text('扫描中...');

                // 开始轮询进度
                progressInterval = setInterval(checkProgress, 2000);
            });
        });

        // 停止扫描
        $('#stop-scan').click(function() {
            if (currentScanId) {
                $.post(`/stop_scan/${currentScanId}`, function(response) {
                    if (response.success) {
                        $('#scan-status').text('扫描已停止');
                        clearInterval(progressInterval);
                        $('#stop-scan').prop('disabled', true);
                        $('#start-scan').prop('disabled', false);
                    }
                });
            }
        });

        // 检查扫描进度
        function checkProgress() {
            if (!currentScanId) return;

            $.get(`/scan_progress/${currentScanId}`, function(progress) {
                if (progress.status === 'running') {
                    // 更新进度条
                    const progressPercent = progress.progress || '0%';
                    $('#progress-bar').css('width', progressPercent).text(progressPercent);
                    $('#remaining-time').text(progress.remaining || '未知');
                    $('#eta').text(progress.eta || '未知');
                    $('#scan-status').text('扫描中...');
                } 
                else if (progress.status === 'completed') {
                    // 扫描完成
                    clearInterval(progressInterval);
                    $('#progress-bar').css('width', '100%').text('100%');
                    $('#scan-status').text('扫描完成');
                    $('#stop-scan').prop('disabled', true);
                    $('#start-scan').prop('disabled', false);

                    // 获取并显示结果
                    loadScanResults(currentScanId);
                } 
                else if (progress.status === 'error') {
                    // 扫描出错
                    clearInterval(progressInterval);
                    $('#progress-bar').css('width', '100%').text('错误');
                    $('#scan-status').text(`错误: ${progress.error || '未知错误'}`);
                    $('#stop-scan').prop('disabled', true);
                    $('#start-scan').prop('disabled', false);
                }
                else if (progress.status === 'stopped') {
                    // 扫描已停止
                    clearInterval(progressInterval);
                    $('#progress-bar').css('width', '100%').text('已停止');
                    $('#scan-status').text('扫描已停止');
                    $('#stop-scan').prop('disabled', true);
                    $('#start-scan').prop('disabled', false);
                }
            });
        }

        // 加载扫描结果
        function loadScanResults(scanId) {
            $.get(`/scan_results/${scanId}`, function(results) {
                if (results.error) {
                    $('#results-container').html(`
                        <div class="alert alert-danger">
                            <h5>扫描出错</h5>
                            <p>${results.error}</p>
                        </div>
                    `);
                } else {
                    let html = `
                        <div class="mb-3">
                            <h5>扫描摘要</h5>
                            <p><strong>命令:</strong> ${results.command}</p>
                            <p><strong>耗时:</strong> ${results.scan_time} 秒</p>
                            <p><strong>发现主机:</strong> ${results.hosts.length}</p>
                        </div>
                    `;

                    results.hosts.forEach(host => {
                        html += `
                            <div class="card mb-3">
                                <div class="card-header ${host.status === 'up' ? 'bg-success' : 'bg-secondary'} text-white">
                                    <h5 class="mb-0">主机: ${host.ip}</h5>
                                </div>
                                <div class="card-body">
                                    <p><strong>主机名:</strong> ${host.hostnames.length > 0 ? host.hostnames[0].name : '未知'}</p>
                                    <p><strong>状态:</strong> ${host.status} (${host.reason})</p>
                                    <p><strong>MAC地址:</strong> ${host.mac || '未知'}</p>

                                    ${host.os && host.os.name ? `
                                        <p><strong>操作系统:</strong> ${host.os.name} (准确率: ${host.os.accuracy}%)</p>
                                    ` : ''}

                                    <h6>开放端口:</h6>
                                    <table class="table table-sm table-bordered">
                                        <thead>
                                            <tr>
                                                <th>端口</th>
                                                <th>协议</th>
                                                <th>服务</th>
                                                <th>状态</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${host.ports.filter(port => port.state === 'open').map(port => `
                                                <tr>
                                                    <td>${port.port}</td>
                                                    <td>${port.protocol}</td>
                                                    <td>${port.service}</td>
                                                    <td><span class="badge bg-success">${port.state}</span></td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        `;
                    });

                    $('#results-container').html(html);
                }

                // 显示结果面板
                $('#results-section').show();

                // 刷新历史记录
                loadScanHistory();
            });
        }

        // 加载扫描历史
        function loadScanHistory() {
            $.get('/scan_history', function(scans) {
                const tbody = $('#history-table tbody');
                tbody.empty();

                scans.forEach(scan => {
                    const startTime = new Date(scan.start_time * 1000).toLocaleString();
                    const duration = Math.round(scan.duration) + '秒';

                    tbody.append(`
                        <tr>
                            <td>${scan.scan_id}</td>
                            <td>${scan.targets}</td>
                            <td>
                                <span class="badge ${scan.status === 'completed' ? 'bg-success' : 
                                    scan.status === 'running' ? 'bg-primary' : 
                                    scan.status === 'error' ? 'bg-danger' : 'bg-secondary'}">
                                    ${scan.status}
                                </span>
                            </td>
                            <td>${startTime}</td>
                            <td>${duration}</td>
                            <td>
                                ${scan.status === 'completed' ? `
                                    <button class="btn btn-sm btn-outline-primary view-result" 
                                            data-scan-id="${scan.scan_id}">
                                        查看结果
                                    </button>
                                ` : ''}
                            </td>
                        </tr>
                    `);
                });

                // 绑定查看结果事件
                $('.view-result').click(function() {
                    const scanId = $(this).data('scan-id');
                    currentScanId = scanId;
                    loadScanResults(scanId);
                    $('#results-section').show();
                    $('html, body').animate({
                        scrollTop: $('#results-section').offset().top
                    }, 500);
                });
            });
        }

        // 页面加载时初始化
        $(document).ready(function() {
            loadScanHistory();
        });
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    # 尝试创建扫描器实例
    try:
        scanner = NmapScanner()
        print("Nmap 扫描器初始化成功!")
    except EnvironmentError as e:
        print(f"初始化错误: {e}")
        print("请确保已安装 Nmap 并添加到系统 PATH")

    # 运行 Flask 应用
    app.run(host='0.0.0.0', port=5000, debug=True)