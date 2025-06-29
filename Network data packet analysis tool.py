import base64
import os
import platform
import sys
from flask import Flask, render_template_string, request, jsonify
from scapy.all import *
import pandas as pd
import plotly
import json
import threading
import time
import subprocess
import traceback
import numpy as np

app = Flask(__name__)

# 全局变量用于控制捕获
capture_active = False
capture_thread = None
packets_df = pd.DataFrame()


class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.capture_interface = None

    def get_interfaces(self):
        """获取可用网络接口列表（跨平台解决方案）"""
        interfaces = []
        try:
            # 跨平台接口获取
            system = platform.system()
            if system == "Windows":
                try:
                    # 使用Scapy的Windows接口列表
                    if_list = get_windows_if_list()
                    interfaces = [iface['name'] for iface in if_list]
                    print(f"Windows接口列表: {interfaces}")
                except Exception as e:
                    print(f"获取Scapy接口列表错误: {e}")
                    # 后备方法：使用netsh命令
                    try:
                        output = subprocess.check_output(['netsh', 'interface', 'show', 'interface'],
                                                         text=True, errors='ignore',
                                                         creationflags=subprocess.CREATE_NO_WINDOW)
                        for line in output.split('\n'):
                            if "Connected" in line or "已连接" in line:
                                parts = line.split()
                                if len(parts) > 3:
                                    # 获取接口名称（可能是多个单词）
                                    name = " ".join(parts[3:])
                                    interfaces.append(name)
                        print(f"netsh接口列表: {interfaces}")
                    except Exception as e2:
                        print(f"netsh命令错误: {e2}")
            elif system == "Darwin":  # macOS
                interfaces = [iface for iface in get_if_list() if iface.startswith('en') or iface.startswith('bridge')]
            else:  # Linux
                interfaces = get_if_list()
        except Exception as e:
            print(f"获取接口错误: {e}")
            traceback.print_exc()

        # 如果获取失败，使用默认值
        if not interfaces:
            interfaces = ["Ethernet", "Wi-Fi", "Local Area Connection", "以太网", "无线网络连接"]
            if system == "Linux":
                interfaces.extend(["eth0", "wlan0", "lo"])

        return list(set(interfaces))  # 去重

    def map_interface_name(self, display_name):
        """将显示名称映射到Scapy可识别的接口名称"""
        try:
            if platform.system() == "Windows":
                # 在Windows上，Scapy使用不同的接口名称
                for iface in get_windows_if_list():
                    if display_name == iface['name']:
                        return iface['name']
                    # 尝试部分匹配
                    if display_name.lower() in iface['name'].lower():
                        return iface['name']
            return display_name
        except:
            return display_name

    def start_live_capture(self, interface, filter_exp="", packet_count=100):
        """实时捕获数据包"""
        global capture_active
        capture_active = True
        self.packets = []
        self.capture_interface = self.map_interface_name(interface)

        print(f"开始捕获: 接口={self.capture_interface}, 过滤器={filter_exp}, 数量={packet_count}")

        if not self.capture_interface:
            print(f"错误: 无法映射接口 '{interface}'")
            return False

        def capture_task():
            try:
                print(f"捕获线程启动...")
                sniff(
                    iface=self.capture_interface,
                    filter=filter_exp,
                    prn=self._process_packet,
                    stop_filter=lambda _: not capture_active or len(self.packets) >= packet_count
                )
                print(f"捕获完成! 捕获了 {len(self.packets)} 个数据包")
            except Exception as e:
                print(f"捕获错误: {e}")
                traceback.print_exc()

        # 在后台线程中运行捕获
        thread = threading.Thread(target=capture_task)
        thread.daemon = True
        thread.start()
        return True

    def stop_capture(self):
        """停止捕获"""
        global capture_active
        capture_active = False
        time.sleep(1)  # 给线程一点时间停止

    def analyze_pcap(self, file_content, filter_exp=""):
        """分析上传的PCAP文件"""
        try:
            # 保存上传的文件内容到临时文件
            temp_file = "temp_" + str(int(time.time())) + ".pcap"
            with open(temp_file, "wb") as f:
                f.write(file_content)

            print(f"分析PCAP文件: {temp_file}, 大小: {len(file_content)} 字节, 过滤器: {filter_exp}")

            # 读取PCAP文件
            self.packets = rdpcap(temp_file)
            print(f"读取了 {len(self.packets)} 个数据包")

            # 应用过滤器
            if filter_exp:
                filtered = []
                for pkt in self.packets:
                    try:
                        if filter_exp.lower() == "tcp" and TCP in pkt:
                            filtered.append(pkt)
                        elif filter_exp.lower() == "udp" and UDP in pkt:
                            filtered.append(pkt)
                        elif filter_exp.lower() == "icmp" and ICMP in pkt:
                            filtered.append(pkt)
                        elif filter_exp.lower() == "dns" and DNS in pkt:
                            filtered.append(pkt)
                        elif filter_exp.lower() == "http" and TCP in pkt and (
                                pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                            filtered.append(pkt)
                        elif filter_exp.lower() == "arp" and ARP in pkt:
                            filtered.append(pkt)
                        else:
                            # 尝试通用过滤
                            if pkt.haslayer(filter_exp):
                                filtered.append(pkt)
                    except:
                        continue
                self.packets = filtered
                print(f"过滤后剩余 {len(self.packets)} 个数据包")

            # 删除临时文件
            os.remove(temp_file)

            return self._to_dataframe()
        except Exception as e:
            print(f"PCAP分析错误: {e}")
            traceback.print_exc()
            return pd.DataFrame()

    def get_captured_packets(self):
        """获取已捕获的数据包"""
        return self._to_dataframe()

    def _process_packet(self, packet):
        """处理每个捕获的数据包"""
        self.packets.append(packet)
        # 每捕获10个包打印一次进度
        if len(self.packets) % 10 == 0:
            print(f"已捕获 {len(self.packets)} 个数据包...")

    def _to_dataframe(self):
        """转换数据包为DataFrame"""
        data = []
        for idx, pkt in enumerate(self.packets):
            try:
                row = {
                    'id': idx + 1,
                    'timestamp': pkt.time,
                    'summary': pkt.summary()
                }

                # IP层信息
                if IP in pkt:
                    row['src'] = pkt[IP].src
                    row['dst'] = pkt[IP].dst
                    row['protocol'] = pkt.sprintf("%IP.proto%")
                elif IPv6 in pkt:
                    row['src'] = pkt[IPv6].src
                    row['dst'] = pkt[IPv6].dst
                    row['protocol'] = pkt.sprintf("%IPv6.nh%")
                else:
                    row['src'] = pkt.src if hasattr(pkt, 'src') else 'N/A'
                    row['dst'] = pkt.dst if hasattr(pkt, 'dst') else 'N/A'
                    row['protocol'] = 'L2'

                # 长度信息
                row['length'] = len(pkt)

                # TCP/UDP端口信息
                if TCP in pkt:
                    row['sport'] = pkt[TCP].sport
                    row['dport'] = pkt[TCP].dport
                elif UDP in pkt:
                    row['sport'] = pkt[UDP].sport
                    row['dport'] = pkt[UDP].dport
                else:
                    row['sport'] = 'N/A'
                    row['dport'] = 'N/A'

                data.append(row)
            except Exception as e:
                print(f"处理数据包错误: {e}")
                continue

        return pd.DataFrame(data)


# 创建捕获器实例
sniffer = PacketSniffer()

# HTML模板保持不变（与之前相同）...

# 简化HTML模板以减小文件大小
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Packet Sniffer</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* 简化样式 */
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.08); }
        header { text-align: center; margin-bottom: 25px; border-bottom: 1px solid #eaeaea; padding-bottom: 15px; }
        h1 { color: #2c3e50; margin: 0; }
        .control-panel { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #eaeaea; }
        .panel-row { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px; }
        .control-group { flex: 1; min-width: 250px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #2c3e50; }
        select, input, .file-upload { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; }
        .button-group { display: flex; gap: 10px; margin-top: 20px; }
        button { flex: 1; padding: 12px 15px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .primary-btn { background: #3498db; color: white; }
        .stop-btn { background: #e74c3c; color: white; }
        .disabled-btn { background: #95a5a6; cursor: not-allowed; }
        .results-section { display: flex; flex-direction: column; gap: 25px; }
        .packet-table-container { overflow-x: auto; border: 1px solid #eaeaea; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background-color: #f8fafc; }
        .stats-container { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; }
        .chart-box { border: 1px solid #eaeaea; border-radius: 8px; padding: 20px; height: 300px; }
        @media (max-width: 768px) { .stats-container { grid-template-columns: 1fr; } }
        .protocol-tag { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: white; }
        .tcp-tag { background: #3498db; }
        .udp-tag { background: #9b59b6; }
        .icmp-tag { background: #2ecc71; }
        .other-tag { background: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>网络数据包分析工具</h1>
            <div class="subtitle">基于Scapy的实时捕获与离线分析</div>
        </header>

        <div class="control-panel">
            <div class="panel-row">
                <div class="control-group">
                    <label for="interfaceSelect">网络接口</label>
                    <select id="interfaceSelect">
                        {% for iface in interfaces %}
                        <option value="{{ iface }}">{{ iface }}</option>
                        {% endfor %}
                    </select>
                </div>

                <div class="control-group">
                    <label for="filterInput">过滤规则 (BPF语法)</label>
                    <input type="text" id="filterInput" placeholder="例如: tcp port 80 or icmp">
                </div>

                <div class="control-group">
                    <label for="packetCount">最大数据包数</label>
                    <input type="number" id="packetCount" value="100" min="1" max="1000">
                </div>
            </div>

            <div class="panel-row">
                <div class="control-group">
                    <label>捕获模式</label>
                    <div style="display: flex; gap: 10px;">
                        <button id="liveModeBtn" class="primary-btn">实时捕获</button>
                        <button id="pcapModeBtn">PCAP分析</button>
                    </div>
                </div>

                <div class="control-group" id="pcapUploadGroup" style="display: none;">
                    <label for="pcapFile">上传PCAP文件</label>
                    <div class="file-upload" onclick="document.getElementById('pcapFile').click()">
                        <div class="file-name" id="fileName">未选择文件</div>
                        <div class="file-button">浏览...</div>
                    </div>
                    <input type="file" id="pcapFile" accept=".pcap,.pcapng" style="display: none;">
                </div>
            </div>

            <div class="button-group">
                <button id="startBtn" class="primary-btn">开始捕获</button>
                <button id="stopBtn" class="stop-btn disabled-btn" disabled>停止捕获</button>
                <button id="clearBtn">清除结果</button>
            </div>
        </div>

        <div class="results-section">
            <div class="packet-table-container">
                <table id="packetTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>时间</th>
                            <th>源地址</th>
                            <th>目标地址</th>
                            <th>协议</th>
                            <th>长度</th>
                            <th>摘要</th>
                        </tr>
                    </thead>
                    <tbody id="packetTableBody">
                        <!-- 数据包将动态填充 -->
                    </tbody>
                </table>
            </div>

            <div class="stats-container">
                <div class="chart-box">
                    <h3 class="chart-title">协议分布</h3>
                    <div id="protocolChart"></div>
                </div>
                <div class="chart-box">
                    <h3 class="chart-title">数据包长度分布</h3>
                    <div id="lengthChart"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script>
        // 全局状态
        let captureActive = false;
        let currentMode = 'live';

        // 元素引用
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        const clearBtn = document.getElementById('clearBtn');
        const liveModeBtn = document.getElementById('liveModeBtn');
        const pcapModeBtn = document.getElementById('pcapModeBtn');
        const pcapUploadGroup = document.getElementById('pcapUploadGroup');
        const pcapFileInput = document.getElementById('pcapFile');
        const fileNameDisplay = document.getElementById('fileName');

        // 更新UI状态
        function updateUIState() {
            // 更新模式按钮
            if (currentMode === 'live') {
                liveModeBtn.classList.add('primary-btn');
                pcapModeBtn.classList.remove('primary-btn');
                pcapUploadGroup.style.display = 'none';
            } else {
                pcapModeBtn.classList.add('primary-btn');
                liveModeBtn.classList.remove('primary-btn');
                pcapUploadGroup.style.display = 'block';
            }

            // 更新按钮状态
            stopBtn.disabled = !captureActive;
            stopBtn.classList.toggle('disabled-btn', !captureActive);
        }

        // 设置捕获模式
        liveModeBtn.addEventListener('click', () => {
            currentMode = 'live';
            updateUIState();
        });

        pcapModeBtn.addEventListener('click', () => {
            currentMode = 'pcap';
            updateUIState();
        });

        // 文件选择处理
        pcapFileInput.addEventListener('change', (e) => {
            fileNameDisplay.textContent = e.target.files[0]?.name || '未选择文件';
        });

        // 开始捕获
        startBtn.addEventListener('click', async () => {
            const interface = document.getElementById('interfaceSelect').value;
            const filter = document.getElementById('filterInput').value;
            const packetCount = parseInt(document.getElementById('packetCount').value) || 100;

            if (currentMode === 'pcap' && (!pcapFileInput.files || pcapFileInput.files.length === 0)) {
                alert('请先上传PCAP文件');
                return;
            }

            captureActive = true;
            updateUIState();

            const formData = new FormData();
            formData.append('interface', interface);
            formData.append('filter', filter);
            formData.append('mode', currentMode);
            formData.append('packet_count', packetCount);

            if (currentMode === 'pcap') {
                formData.append('pcap_file', pcapFileInput.files[0]);
            }

            try {
                const response = await fetch('/start_capture', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.status === 'success') {
                    // 开始轮询结果
                    pollCaptureResults();
                } else {
                    alert('错误: ' + result.message);
                    captureActive = false;
                    updateUIState();
                }
            } catch (error) {
                console.error('捕获失败:', error);
                alert('捕获失败: ' + error.message);
                captureActive = false;
                updateUIState();
            }
        });

        // 停止捕获
        stopBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/stop_capture', { method: 'POST' });
                const result = await response.json();

                if (result.status === 'success') {
                    captureActive = false;
                    updateUIState();
                    // 获取最终结果
                    fetchResults();
                }
            } catch (error) {
                console.error('停止捕获失败:', error);
            }
        });

        // 清除结果
        clearBtn.addEventListener('click', () => {
            document.getElementById('packetTableBody').innerHTML = '';
            Plotly.purge('protocolChart');
            Plotly.purge('lengthChart');
        });

        // 轮询捕获结果
        function pollCaptureResults() {
            if (!captureActive) return;

            fetchResults();
            setTimeout(pollCaptureResults, 2000); // 每2秒轮询一次
        }

        // 获取结果并更新UI
        async function fetchResults() {
            try {
                const response = await fetch('/get_packets');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();

                if (data.packets && data.packets.length > 0) {
                    renderPacketTable(data.packets);
                }

                if (data.protocol_chart) {
                    Plotly.react('protocolChart', JSON.parse(data.protocol_chart));
                }

                if (data.length_chart) {
                    Plotly.react('lengthChart', JSON.parse(data.length_chart));
                }
            } catch (error) {
                console.error('获取结果失败:', error);
            }
        }

        // 渲染数据包表格
        function renderPacketTable(packets) {
            const tbody = document.getElementById('packetTableBody');
            tbody.innerHTML = '';

            packets.forEach(pkt => {
                const row = document.createElement('tr');

                // 格式化时间戳
                const date = new Date(pkt.timestamp * 1000);
                const timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;

                // 协议标签
                let protocolClass = 'other-tag';
                if (pkt.protocol === 'TCP' || pkt.protocol === '6') protocolClass = 'tcp-tag';
                else if (pkt.protocol === 'UDP' || pkt.protocol === '17') protocolClass = 'udp-tag';
                else if (pkt.protocol === 'ICMP' || pkt.protocol === '1') protocolClass = 'icmp-tag';

                const protocolName = pkt.protocol === '6' ? 'TCP' : 
                                    pkt.protocol === '17' ? 'UDP' : 
                                    pkt.protocol === '1' ? 'ICMP' : 
                                    pkt.protocol;

                row.innerHTML = `
                    <td>${pkt.id}</td>
                    <td>${timeStr}</td>
                    <td>${pkt.src}</td>
                    <td>${pkt.dst}</td>
                    <td><span class="protocol-tag ${protocolClass}">${protocolName}</span></td>
                    <td>${pkt.length}</td>
                    <td>${pkt.summary}</td>
                `;

                tbody.appendChild(row);
            });
        }

        // 初始化UI
        updateUIState();
    </script>
</body>
</html>
'''


# Flask路由
@app.route('/')
def index():
    try:
        interfaces = sniffer.get_interfaces()
        print(f"可用的网络接口: {interfaces}")
        return render_template_string(HTML_TEMPLATE, interfaces=interfaces, capture_active=capture_active)
    except Exception as e:
        traceback.print_exc()
        return f"<h1>内部服务器错误</h1><p>{str(e)}</p><pre>{traceback.format_exc()}</pre>", 500


@app.route('/start_capture', methods=['POST'])
def start_capture():
    try:
        # 获取参数
        interface = request.form.get('interface')
        filter_exp = request.form.get('filter', '')
        mode = request.form.get('mode', 'live')
        packet_count = int(request.form.get('packet_count', 100))

        print(f"开始捕获请求: 接口={interface}, 过滤器={filter_exp}, 模式={mode}, 数量={packet_count}")

        if mode == 'live':
            # 开始实时捕获
            success = sniffer.start_live_capture(interface, filter_exp, packet_count)
            if not success:
                return jsonify({'status': 'error', 'message': f'无法在接口 {interface} 上开始捕获'})

            return jsonify({
                'status': 'success',
                'message': f'开始在 {interface} 上捕获数据包...'
            })
        elif mode == 'pcap':
            # 处理PCAP文件
            if 'pcap_file' not in request.files:
                return jsonify({'status': 'error', 'message': '未提供PCAP文件'})

            pcap_file = request.files['pcap_file']
            if pcap_file.filename == '':
                return jsonify({'status': 'error', 'message': '未选择文件'})

            # 分析PCAP文件
            packets_df = sniffer.analyze_pcap(pcap_file.read(), filter_exp)
            return jsonify({
                'status': 'success',
                'message': f'成功分析 {len(packets_df)} 个数据包'
            })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    try:
        sniffer.stop_capture()
        return jsonify({'status': 'success', 'message': '捕获已停止'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/get_packets')
def get_packets():
    try:
        # 获取捕获的数据包
        packets_df = sniffer.get_captured_packets()

        # 准备图表数据
        protocol_chart = None
        length_chart = None

        if not packets_df.empty and not packets_df.empty:
            # 协议分布图
            if 'protocol' in packets_df.columns:
                protocol_counts = packets_df['protocol'].value_counts().reset_index()
                protocol_counts.columns = ['protocol', 'count']

                # 将Pandas DataFrame转换为Python原生数据结构
                protocol_data = [{
                    'values': protocol_counts['count'].tolist(),  # 转换为列表
                    'labels': protocol_counts['protocol'].tolist(),  # 转换为列表
                    'type': 'pie',
                    'hole': 0.4,
                    'marker': {'colors': ['#3498db', '#9b59b6', '#2ecc71', '#e74c3c', '#f39c12']}
                }]

                protocol_chart = json.dumps(protocol_data)

            # 包长度分布图
            if 'length' in packets_df.columns:
                # 将Pandas Series转换为Python原生列表
                length_data = [{
                    'x': packets_df['length'].tolist(),  # 转换为列表
                    'type': 'histogram',
                    'nbinsx': 20,
                    'marker': {'color': '#3498db'}
                }]

                length_chart = json.dumps(length_data)

        # 限制返回的数据包数量并转换为字典列表
        packets_data = []
        if not packets_df.empty:
            # 转换DataFrame为字典列表
            packets_data = packets_df.head(100).to_dict(orient='records')

        return jsonify({
            'packets': packets_data,
            'protocol_chart': protocol_chart,
            'length_chart': length_chart
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500


if __name__ == '__main__':
    # 在Windows上可能需要管理员权限
    print("=" * 50)
    print("启动数据包捕获工具")
    print("注意: 在Windows/Linux上可能需要管理员/root权限")
    interfaces = sniffer.get_interfaces()
    print("可用的网络接口:", interfaces)
    print("=" * 50)

    # 设置调试模式
    app.run(debug=True, port=5000, use_reloader=False)