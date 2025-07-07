#!/usr/bin/env python3
"""
基于Python的网络入侵检测系统 - Web版本
整合为单一文件，包含所有HTML模板
"""
import sys
import os
import re
import time
import json
import logging
import sqlite3
import threading
import argparse
import platform
import random
import atexit
import hashlib
import functools
from collections import defaultdict
from datetime import datetime
from logging.handlers import SMTPHandler, SysLogHandler
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, flash, Response
from flask_socketio import SocketIO, emit
from markupsafe import escape

# ======================= HTML 模板 =======================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>NIDS 仪表盘</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.7.4/dist/socket.io.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        .stats-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .stat-card { text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; margin: 10px 0; }
        .controls { display: flex; gap: 10px; margin-bottom: 20px; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-danger { background-color: #dc3545; color: white; }
        .btn-success { background-color: #28a745; color: white; }
        .chart-container { height: 300px; margin-top: 20px; }
        .alert-badge { position: absolute; top: -8px; right: -8px; background-color: red; color: white; border-radius: 50%; width: 20px; height: 20px; display: flex; justify-content: center; align-items: center; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>网络入侵检测系统</h1>
            <div>
                <a href="{{ url_for('alerts_page') }}" class="btn" style="position: relative;">
                    警报
                    {% if config.test_mode or is_running %}
                    <span id="alert-count" class="alert-badge">0</span>
                    {% endif %}
                </a>
                <a href="{{ url_for('settings_page') }}" class="btn">设置</a>
                <a href="{{ url_for('logout') }}" class="btn">退出</a>
            </div>
        </div>

        <div class="controls">
            {% if is_running %}
                <button id="stop-btn" class="btn btn-danger">停止监控</button>
            {% else %}
                <button id="start-btn" class="btn btn-primary">开始监控</button>
            {% endif %}
            <button id="clear-btn" class="btn">清除警报</button>
            <label>
                <input type="checkbox" id="test-mode" {% if config.test_mode %}checked{% endif %}>
                测试模式
            </label>
        </div>

        <div class="stats-container">
            <div class="card stat-card">
                <h3>运行时间</h3>
                <div id="uptime" class="stat-value">00:00:00</div>
            </div>
            <div class="card stat-card">
                <h3>数据包数量</h3>
                <div id="packet-count" class="stat-value">0</div>
            </div>
            <div class="card stat-card">
                <h3>警报数量</h3>
                <div id="alert-count-value" class="stat-value">0</div>
            </div>
        </div>

        <div class="card">
            <h2>协议分布</h2>
            <div class="chart-container">
                <canvas id="protocol-chart"></canvas>
            </div>
        </div>

        <div class="card">
            <h2>流量来源</h2>
            <div class="chart-container">
                <canvas id="source-chart"></canvas>
            </div>
        </div>

        <div class="card">
            <h2>活动连接</h2>
            <table id="connections-table" style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid #ddd;">
                        <th style="text-align: left; padding: 8px;">来源IP</th>
                        <th style="text-align: left; padding: 8px;">目标IP</th>
                        <th style="text-align: left; padding: 8px;">协议</th>
                        <th style="text-align: right; padding: 8px;">数据包数量</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- 连接数据将通过JavaScript填充 -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // 建立Socket.IO连接
        const socket = io();

        // 初始化图表
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        const protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#8AC926', '#1982C4', '#6A4C93', '#F15BB5'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        const sourceCtx = document.getElementById('source-chart').getContext('2d');
        const sourceChart = new Chart(sourceCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: '数据包数量',
                    data: [],
                    backgroundColor: '#36A2EB'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // 监听统计更新
        socket.on('stats_update', function(data) {
            // 更新基本统计
            document.getElementById('uptime').textContent = data.uptime_str;
            document.getElementById('packet-count').textContent = data.packet_count;
            document.getElementById('alert-count-value').textContent = data.alert_count;
            document.getElementById('alert-count').textContent = data.alert_count;

            // 更新协议图表
            protocolChart.data.labels = data.protocol_data.map(item => item.protocol);
            protocolChart.data.datasets[0].data = data.protocol_data.map(item => item.count);
            protocolChart.update();

            // 更新来源图表
            sourceChart.data.labels = data.source_data.map(item => item.ip);
            sourceChart.data.datasets[0].data = data.source_data.map(item => item.count);
            sourceChart.update();

            // 更新连接表格
            const tableBody = document.querySelector('#connections-table tbody');
            tableBody.innerHTML = '';

            if (data.connections && data.connections.length > 0) {
                data.connections.forEach(conn => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td style="padding: 8px;">${conn.src_ip}</td>
                        <td style="padding: 8px;">${conn.dst_ip}</td>
                        <td style="padding: 8px;">${conn.protocol}</td>
                        <td style="padding: 8px; text-align: right;">${conn.count}</td>
                    `;
                    tableBody.appendChild(row);
                });
            }
        });

        // 监听新警报
        socket.on('new_alerts', function(data) {
            // 可以在这里添加通知逻辑
            console.log(`收到 ${data.count} 条新警报`);
        });

        // 按钮事件处理
        document.getElementById('start-btn')?.addEventListener('click', function() {
            fetch('/start_monitoring')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        window.location.reload();
                    } else {
                        alert('启动失败: ' + data.message);
                    }
                });
        });

        document.getElementById('stop-btn')?.addEventListener('click', function() {
            fetch('/stop_monitoring')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        window.location.reload();
                    }
                });
        });

        document.getElementById('clear-btn').addEventListener('click', function() {
            if (confirm('确定要清除所有警报吗？')) {
                fetch('/clear_alerts')
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            document.getElementById('alert-count-value').textContent = '0';
                            document.getElementById('alert-count').textContent = '0';
                        }
                    });
            }
        });

        document.getElementById('test-mode').addEventListener('change', function() {
            fetch(`/toggle_test_mode?enable=${this.checked}`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        console.log(`测试模式已${data.test_mode ? '启用' : '禁用'}`);
                    }
                });
        });
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>登录 - NIDS</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background-color: #f5f5f5; 
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-weight: bold;
            color: #555;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #0069d9;
        }
        .alert {
            padding: 10px;
            margin-bottom: 16px;
            border-radius: 4px;
            text-align: center;
        }
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .flash-messages {
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>网络入侵检测系统</h1>

        <div class="flash-messages">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>

        <form method="POST">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" required>
            </div>

            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
"""

ALERTS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>警报 - NIDS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-danger { background-color: #dc3545; color: white; }
        .btn-success { background-color: #28a745; color: white; }
        .alerts-table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .alerts-table th, .alerts-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        .alerts-table th { background-color: #f8f9fa; font-weight: bold; }
        .alerts-table tr:hover { background-color: #f1f1f1; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .controls { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .back-btn { margin-right: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>入侵警报</h1>
            <div>
                <a href="{{ url_for('dashboard') }}" class="btn back-btn">返回仪表盘</a>
                <a href="{{ url_for('export_alerts') }}" class="btn btn-success">导出为CSV</a>
            </div>
        </div>

        <div class="controls">
            <button id="clear-btn" class="btn btn-danger">清除所有警报</button>
        </div>

        <table class="alerts-table">
            <thead>
                <tr>
                    <th>时间</th>
                    <th>规则名称</th>
                    <th>严重性</th>
                    <th>来源IP</th>
                    <th>目标IP</th>
                    <th>协议</th>
                    <th>负载</th>
                </tr>
            </thead>
            <tbody>
                {% for alert in alerts %}
                <tr>
                    <td>{{ datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S') }}</td>
                    <td>{{ alert.rule_name }}</td>
                    <td class="severity-{% if alert.severity >= 4 %}high{% elif alert.severity >= 3 %}medium{% else %}low{% endif %}">
                        {{ alert.severity }}
                    </td>
                    <td>{{ alert.src_ip }}</td>
                    <td>{{ alert.dst_ip }}</td>
                    <td>{{ alert.protocol }}</td>
                    <td>{{ alert.payload|truncate(50) }}</td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="7" style="text-align: center;">没有警报记录</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        document.getElementById('clear-btn').addEventListener('click', function() {
            if (confirm('确定要清除所有警报吗？此操作不可撤销。')) {
                fetch('/clear_alerts')
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            window.location.reload();
                        }
                    });
            }
        });
    </script>
</body>
</html>
"""

SETTINGS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>设置 - NIDS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 25px; margin-bottom: 25px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="text"], input[type="password"], input[type="number"], select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .checkbox-group { display: flex; align-items: center; }
        .checkbox-group input { width: auto; margin-right: 10px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background-color: #007bff; color: white; }
        .back-btn { margin-right: 10px; }
        .section-title { border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
        .form-row { display: flex; gap: 15px; margin-bottom: 15px; }
        .form-row .form-group { flex: 1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>系统设置</h1>
            <a href="{{ url_for('dashboard') }}" class="btn back-btn">返回仪表盘</a>
        </div>

        <form method="POST">
            <div class="card">
                <h2 class="section-title">网络设置</h2>

                <div class="form-group">
                    <label for="interface">网络接口</label>
                    <input type="text" id="interface" name="interface" value="{{ config.interface }}" required>
                </div>

                <div class="form-group">
                    <label for="filter">流量过滤规则</label>
                    <input type="text" id="filter" name="filter" value="{{ config.capture_filter }}">
                </div>
            </div>

            <div class="card">
                <h2 class="section-title">警报设置</h2>

                <div class="checkbox-group">
                    <input type="checkbox" id="email_enabled" name="email_enabled" {% if config.email_enabled %}checked{% endif %}>
                    <label for="email_enabled">启用邮件警报</label>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="smtp_server">SMTP服务器</label>
                        <input type="text" id="smtp_server" name="smtp_server" value="{{ config.smtp_server }}">
                    </div>

                    <div class="form-group">
                        <label for="smtp_port">SMTP端口</label>
                        <input type="number" id="smtp_port" name="smtp_port" value="{{ config.smtp_port }}">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="smtp_user">SMTP用户名</label>
                        <input type="text" id="smtp_user" name="smtp_user" value="{{ config.smtp_user }}">
                    </div>

                    <div class="form-group">
                        <label for="smtp_password">SMTP密码</label>
                        <input type="password" id="smtp_password" name="smtp_password" value="{{ config.smtp_password }}">
                    </div>
                </div>

                <div class="form-group">
                    <label for="to_emails">接收警报邮箱 (多个邮箱用逗号分隔)</label>
                    <textarea id="to_emails" name="to_emails">{{ config.to_emails|join(', ') }}</textarea>
                </div>
            </div>

            <div class="card">
                <h2 class="section-title">系统设置</h2>

                <div class="checkbox-group">
                    <input type="checkbox" id="test_mode" name="test_mode" {% if config.test_mode %}checked{% endif %}>
                    <label for="test_mode">启用测试模式</label>
                </div>
            </div>

            <div class="form-group">
                <button type="submit" class="btn btn-primary">保存设置</button>
            </div>
        </form>
    </div>
</body>
</html>
"""


# ======================= 系统配置和核心类 =======================

# 系统配置
class Config:
    def __init__(self):
        self.interface = self.get_default_interface()
        self.capture_filter = 'tcp or udp'
        self.log_file = 'nids.log'
        self.db_file = 'nids.db'  # 使用当前目录
        self.rule_file = 'nids_rules.rules'
        self.model_file = 'anomaly_model.joblib'
        self.test_mode = False  # 添加测试模式标志
        self.web_port = 5000
        self.web_debug = False
        self.web_secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
        self.web_username = "admin"
        self.web_password = "admin123"

        # 邮件警报设置
        self.email_enabled = False
        self.smtp_server = 'smtp.example.com'
        self.smtp_port = 587
        self.smtp_user = 'alerts@example.com'
        self.smtp_password = 'password'
        self.to_emails = ['admin@example.com']

        # Syslog设置
        self.syslog_enabled = False
        self.syslog_server = 'localhost'
        self.syslog_port = 514

        # 控制台输出
        self.console_output = True
        self.packet_debug = False

    def get_default_interface(self):
        """获取默认网络接口"""
        if platform.system() == "Windows":
            return "Ethernet"
        elif platform.system() == "Darwin":  # macOS
            return "en0"
        else:  # Linux
            return "eth0"


# 数据包捕获模块
class PacketCapturer:
    def __init__(self, config):
        self.config = config
        self.capture = None
        self.running = False
        self.packet_count = 0
        self.capture_thread = None
        self.test_timer = None

    def start_capture(self, packet_handler):
        """开始实时捕获数据包"""
        if self.running:
            return False

        self.running = True

        # 测试模式
        if self.config.test_mode:
            logging.info("启动测试模式，生成模拟数据...")
            self.test_timer = threading.Timer(0.1, self.generate_test_packet, args=[packet_handler])
            self.test_timer.daemon = True
            self.test_timer.start()
            return True

        # 正常捕获模式
        try:
            import pyshark
            self.capture = pyshark.LiveCapture(
                interface=self.config.interface,
                display_filter=self.config.capture_filter,
                output_file=None
            )
        except ImportError:
            logging.error("pyshark库未安装，无法捕获真实数据包")
            return False
        except Exception as e:
            logging.error(f"捕获初始化失败: {str(e)}")
            return False

        def capture_loop():
            try:
                for packet in self.capture.sniff_continuously():
                    if not self.running:
                        break
                    try:
                        parsed_packet = self._parse_packet(packet)
                        self.packet_count += 1
                        packet_handler(parsed_packet)
                    except Exception as e:
                        logging.error(f"数据包处理错误: {str(e)}")
            except Exception as e:
                logging.critical(f"捕获错误: {str(e)}")
                self.running = False

        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
        logging.info(f"开始在 {self.config.interface} 上捕获流量...")
        return True

    def _parse_packet(self, packet):
        """解析数据包为结构化数据"""
        result = {
            'timestamp': packet.sniff_time.timestamp(),
            'src_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
            'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else '0.0.0.0',
            'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'OTHER',
            'length': int(packet.length),
            'payload': None
        }

        # 获取端口信息
        try:
            result['src_port'] = packet[packet.transport_layer].srcport
            result['dst_port'] = packet[packet.transport_layer].dstport
        except:
            result['src_port'] = 0
            result['dst_port'] = 0

        # 获取有效载荷
        if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
            try:
                result['payload'] = packet.data.data.binary_value.decode('utf-8', 'ignore')
            except:
                result['payload'] = str(packet.data.data)

        return result

    def stop_capture(self):
        """停止捕获"""
        if self.running:
            logging.info("正在停止捕获...")
            self.running = False
            if self.capture:
                self.capture.close()
            if self.test_timer:
                self.test_timer.cancel()
            logging.info("捕获已停止")

    def generate_test_packet(self, packet_handler):
        """生成测试数据包用于系统测试"""
        if not self.running:
            return

        try:
            # 随机生成正常或异常数据包
            if random.random() < 0.8:  # 80%的概率生成正常数据包
                packet = self._generate_normal_packet()
            else:  # 20%的概率生成异常数据包
                packet = self._generate_alert_packet()

            self.packet_count += 1
            packet_handler(packet)

            # 安排下一个测试数据包
            self.test_timer = threading.Timer(0.1, self.generate_test_packet, args=[packet_handler])
            self.test_timer.daemon = True
            self.test_timer.start()
        except Exception as e:
            logging.error(f"生成测试数据包错误: {str(e)}")

    def _generate_normal_packet(self):
        """生成正常流量数据包"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        src_ips = ['192.168.1.' + str(i) for i in range(1, 50)]
        dst_ips = ['10.0.0.' + str(i) for i in range(1, 20)] + ['8.8.8.8', '1.1.1.1']
        ports = [80, 443, 53, 22, 21, 25, 110]

        payloads = [
            "GET /index.html HTTP/1.1",
            "POST /login HTTP/1.1",
            "DNS query: www.example.com",
            "SSH connection established",
            "FTP file transfer complete",
            "SMTP email sent successfully",
            "TLS handshake completed"
        ]

        return {
            'timestamp': time.time(),
            'src_ip': random.choice(src_ips),
            'dst_ip': random.choice(dst_ips),
            'protocol': random.choice(protocols),
            'src_port': str(random.choice(ports)),  # 确保端口是字符串
            'dst_port': str(random.choice(ports)),  # 确保端口是字符串
            'length': random.randint(64, 1500),
            'payload': random.choice(payloads)
        }

    def _generate_alert_packet(self):
        """生成触发警报的数据包"""
        attack_types = [
            ("SQL注入攻击", "SELECT * FROM users WHERE username = 'admin' OR 1=1--"),
            ("跨站脚本攻击", "<script>alert('XSS')</script>"),
            ("目录遍历攻击", "../../etc/passwd"),
            ("暴力破解尝试", "Failed password for root"),
            ("恶意PowerShell",
             "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA"),
            ("命令注入", "| cat /etc/passwd"),
            ("数据泄露", "Credit Card: 4111 1111 1111 1111"),
            ("Web Shell", "<?php system($_GET['cmd']); ?>"),
            ("加密货币挖矿", "stratum+tcp://xmr.pool.minergate.com:45560"),
            ("钓鱼尝试", "Please login to verify your account: http://fake-bank.com/login")
        ]

        src_ips = ['192.168.1.' + str(i) for i in range(100, 150)]
        dst_ips = ['10.0.0.' + str(i) for i in range(1, 20)] + ['192.168.1.1']
        protocols = ['TCP', 'UDP']
        ports = [80, 443, 22, 21, 25]

        attack_name, payload = random.choice(attack_types)

        return {
            'timestamp': time.time(),
            'src_ip': random.choice(src_ips),
            'dst_ip': random.choice(dst_ips),
            'protocol': random.choice(protocols),
            'src_port': str(random.choice(ports)),  # 确保端口是字符串
            'dst_port': str(random.choice(ports)),  # 确保端口是字符串
            'length': random.randint(200, 1500),
            'payload': payload,
            'is_attack': True,  # 明确标记为攻击包
            'attack_name': attack_name  # 添加攻击名称
        }


# 流量分析模块
class TrafficAnalyzer:
    def __init__(self, config):
        self.config = config
        self.connections = defaultdict(list)
        self.stats = {
            'start_time': time.time(),
            'packet_count': 0,
            'alert_count': 0,
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'last_update': time.time()
        }

    def analyze(self, packet):
        """分析网络流量"""
        self.stats['packet_count'] += 1

        # 更新协议统计
        self.stats['protocols'][packet['protocol']] += 1

        # 更新源和目标统计
        self.stats['top_sources'][packet['src_ip']] += 1
        self.stats['top_destinations'][packet['dst_ip']] += 1

        # 记录连接
        conn_key = (packet['src_ip'], packet['dst_ip'], packet['protocol'])
        self.connections[conn_key].append(packet)

        # 定期更新统计
        current_time = time.time()
        if current_time - self.stats['last_update'] > 30:  # 每30秒更新一次
            self._update_stats()
            self.stats['last_update'] = current_time

        return self.stats

    def increment_alert(self):
        """增加警报计数"""
        self.stats['alert_count'] += 1

    def reset_alert_count(self):
        """重置警报计数"""
        self.stats['alert_count'] = 0

    def _update_stats(self):
        """更新流量统计信息"""
        # 计算最活跃的连接
        active_conns = [(k, len(v)) for k, v in self.connections.items()]
        if active_conns:
            active_conns.sort(key=lambda x: x[1], reverse=True)
            self.stats['top_connections'] = active_conns[:5]

        # 重置连接记录
        self.connections.clear()

        # 更新运行时间
        self.stats['uptime'] = time.time() - self.stats['start_time']

        # 记录统计信息
        logging.debug(f"流量统计: {json.dumps(self.stats, indent=2, default=str)}")

    def get_stats(self):
        """获取当前统计信息"""
        return self.stats


# 规则检测引擎
class RuleEngine:
    def __init__(self, config):
        self.config = config
        self.rules = self._load_rules()

    def _load_rules(self):
        """加载入侵检测规则"""
        rules = []
        # 修复无效的正则表达式
        default_rules = [
            "1001||SQL Injection||(union\\s+select)|(select\\s+.*from)||4",
            "1002||XSS Attempt||<script>|javascript:||3",
            "1003||Directory Traversal||(\\.\\./)|(\\.\\.\\\\)||3",
            "1004||SSH Bruteforce||(ssh)|(password)||3",
            "1005||Suspicious PowerShell||powershell.*-e||4",
            # 修复无效的正则表达式
            "1006||Command Injection||(\\|\\|)|(\\&\\&)|(;)|(`)|(\\bexec\\s*\\()||3",
            "1007||Data Exfiltration||(\\bpassw)|(\\bcredit)|(\\bssn\\b)||3",
            "1008||Web Shell||(\\bcmd\\.exe)|(\\/bin\\/sh)|(\\/bin\\/bash)||4",
            "1009||Cryptocurrency Miner||(xmr)|(monero)|(cryptonight)||2",
            "1010||Phishing Attempt||(\\blogin\\b)|(\\bpassword\\b)|(\\baccount\\b)||2"
        ]

        # 尝试加载规则文件
        if os.path.exists(self.config.rule_file):
            try:
                with open(self.config.rule_file, 'r') as f:
                    rule_lines = f.readlines()
                logging.info(f"从文件加载规则: {self.config.rule_file}")
            except Exception as e:
                logging.error(f"加载规则文件失败: {str(e)}")
                rule_lines = default_rules
        else:
            logging.info(f"规则文件不存在，使用内置规则: {self.config.rule_file}")
            rule_lines = default_rules

        for line in rule_lines:
            if isinstance(line, bytes):
                line = line.decode('utf-8')
            if line.startswith('#') or not line.strip():
                continue
            parts = line.strip().split('||')
            if len(parts) >= 3:
                try:
                    # 修复无效的正则表达式
                    pattern = parts[2].replace('\\\\', '\\')  # 处理转义字符
                    rules.append({
                        'id': parts[0],
                        'name': parts[1],
                        'pattern': re.compile(pattern, re.IGNORECASE),
                        'severity': int(parts[3]) if len(parts) > 3 else 3
                    })
                    logging.debug(f"加载规则: {parts[1]}")
                except re.error as e:
                    logging.error(f"无效的正则表达式 '{parts[2]}': {str(e)}")
                except Exception as e:
                    logging.error(f"加载规则错误: {str(e)}")

        logging.info(f"已加载 {len(rules)} 条检测规则")
        return rules

    def detect(self, packet):
        """根据规则检测数据包"""
        alerts = []
        if not packet['payload']:
            return alerts

        for rule in self.rules:
            try:
                if rule['pattern'].search(packet['payload']):
                    alerts.append({
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'packet': packet
                    })
            except Exception as e:
                logging.error(f"规则匹配错误: {str(e)}")
        return alerts


# 异常检测引擎
class AnomalyDetector:
    def __init__(self, config):
        self.config = config
        self.model = None
        self.features = []
        self.MAX_FEATURES = 500
        self.training_interval = 300  # 5分钟
        self.last_training = 0

        try:
            from sklearn.ensemble import IsolationForest
            import joblib
            import numpy as np
            self.ML_ENABLED = True
            self._load_model()
        except ImportError:
            logging.warning("scikit-learn未安装，异常检测功能将不可用")
            self.ML_ENABLED = False

    def _load_model(self):
        """加载或创建异常检测模型"""
        if not self.ML_ENABLED:
            return

        try:
            if os.path.exists(self.config.model_file):
                import joblib
                self.model = joblib.load(self.config.model_file)
                logging.info(f"从 {self.config.model_file} 加载异常检测模型")
            else:
                from sklearn.ensemble import IsolationForest
                self.model = IsolationForest(n_estimators=50, contamination=0.01, random_state=42)
                logging.info("创建新的异常检测模型")
        except Exception as e:
            logging.error(f"加载模型失败: {str(e)}")
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(n_estimators=50, contamination=0.01, random_state=42)
            logging.info("创建新的异常检测模型作为后备")

    def extract_features(self, packet):
        """从数据包中提取特征"""
        return [
            len(packet['payload'] or ''),
            packet['length'],
            int(packet.get('src_port', 0)),
            int(packet.get('dst_port', 0)),
            len(packet['src_ip'].split('.')),
            len(packet['dst_ip'].split('.'))
        ]

    def detect(self, packet):
        """检测异常数据包"""
        if not self.ML_ENABLED or not self.model:
            return False

        features = self.extract_features(packet)
        self.features.append(features)

        # 定期重新训练模型
        current_time = time.time()
        if current_time - self.last_training > self.training_interval:
            self._train_model()
            self.last_training = current_time

        # 预测异常
        if len(self.features) > 10:  # 有足够数据时开始预测
            try:
                prediction = self.model.predict([features])
                if prediction[0] == -1:
                    return True
            except Exception as e:
                logging.error(f"异常检测错误: {str(e)}")
        return False

    def _train_model(self):
        """训练异常检测模型"""
        if len(self.features) < 50:  # 最少需要50个样本
            return

        try:
            import numpy as np
            import joblib
            X = np.array(self.features)
            self.model.fit(X)
            joblib.dump(self.model, self.config.model_file)
            logging.info(f"异常检测模型已更新，样本数: {len(self.features)}")
            self.features = []  # 重置特征集
        except Exception as e:
            logging.error(f"模型训练错误: {str(e)}")


# 警报与日志系统
class AlertSystem:
    def __init__(self, config, analyzer):
        self.config = config
        self.analyzer = analyzer
        self.logger = logging.getLogger('NIDS')
        self.logger.setLevel(logging.INFO)

        # 文件日志
        file_handler = logging.FileHandler(config.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

        # 控制台日志
        if config.console_output:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            self.logger.addHandler(console_handler)

        # 邮件警报
        if config.email_enabled:
            try:
                mail_handler = SMTPHandler(
                    mailhost=(config.smtp_server, config.smtp_port),
                    fromaddr=config.smtp_user,
                    toaddrs=config.to_emails,
                    subject='NIDS Alert',
                    credentials=(config.smtp_user, config.smtp_password),
                    secure=()
                )
                mail_handler.setLevel(logging.WARNING)
                self.logger.addHandler(mail_handler)
                logging.info("邮件警报已启用")
            except Exception as e:
                logging.error(f"邮件警报配置失败: {str(e)}")

        # 系统日志
        if config.syslog_enabled:
            try:
                syslog_handler = SysLogHandler(address=(config.syslog_server, config.syslog_port))
                self.logger.addHandler(syslog_handler)
                logging.info("Syslog警报已启用")
            except Exception as e:
                logging.error(f"Syslog配置失败: {str(e)}")

        # 初始化数据库
        self._init_database()

    def _init_database(self):
        """初始化警报数据库"""
        try:
            # 确保目录存在 - 使用当前目录
            db_dir = os.path.dirname(self.config.db_file)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                logging.info(f"创建数据库目录: {db_dir}")

            conn = sqlite3.connect(self.config.db_file)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                         id INTEGER PRIMARY KEY,
                         timestamp REAL,
                         rule_id TEXT,
                         rule_name TEXT,
                         severity INTEGER,
                         src_ip TEXT,
                         dst_ip TEXT,
                         protocol TEXT,
                         payload TEXT)''')
            conn.commit()
            conn.close()
            logging.info(f"数据库初始化成功: {self.config.db_file}")
        except Exception as e:
            logging.error(f"数据库初始化失败: {str(e)}")

    def log_alert(self, alert):
        """记录入侵警报"""
        self.analyzer.increment_alert()

        packet = alert['packet']
        log_entry = {
            'timestamp': time.time(),
            'rule_id': alert.get('rule_id', 'ANOMALY'),
            'rule_name': alert.get('rule_name', 'Anomalous Behavior'),
            'severity': alert.get('severity', 2),
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'protocol': packet['protocol'],
            'payload': packet.get('payload', '')[:500]  # 限制长度
        }

        # 保存到数据库
        try:
            conn = sqlite3.connect(self.config.db_file)
            c = conn.cursor()
            c.execute('''INSERT INTO alerts 
                         (timestamp, rule_id, rule_name, severity, src_ip, dst_ip, protocol, payload)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (log_entry['timestamp'], log_entry['rule_id'], log_entry['rule_name'],
                       log_entry['severity'], log_entry['src_ip'], log_entry['dst_ip'],
                       log_entry['protocol'], log_entry['payload']))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"数据库错误: {str(e)}")

        # 根据严重级别记录
        msg = (f"警报 [{log_entry['severity']}]: {log_entry['rule_name']} "
               f"({log_entry['src_ip']} -> {log_entry['dst_ip']} {log_entry['protocol']})")

        if log_entry['severity'] >= 4:
            self.logger.critical(msg)
        elif log_entry['severity'] >= 3:
            self.logger.error(msg)
        else:
            self.logger.warning(msg)

        return log_entry


# 主系统
class NetworkIDS:
    def __init__(self, config):
        self.config = config
        self.analyzer = TrafficAnalyzer(config)
        self.capturer = PacketCapturer(config)
        self.rule_engine = RuleEngine(config)
        self.anomaly_detector = AnomalyDetector(config)
        self.alert_system = AlertSystem(config, self.analyzer)
        self.running = False
        self.last_alert_count = 0

        # 注册退出处理
        atexit.register(self.stop)

    def start(self):
        """启动入侵检测系统"""
        if self.running:
            return False

        logging.info("启动网络入侵检测系统")
        self.running = True
        return self.capturer.start_capture(self.process_packet)

    def process_packet(self, packet):
        """处理捕获的数据包"""
        try:
            # 流量分析
            self.analyzer.analyze(packet)

            # 基于规则的检测
            rule_alerts = self.rule_engine.detect(packet)
            for alert in rule_alerts:
                self.alert_system.log_alert(alert)

            # 基于异常的检测
            if self.anomaly_detector.ML_ENABLED and self.anomaly_detector.detect(packet):
                self.alert_system.log_alert({
                    'rule_name': '异常行为检测',
                    'severity': 3,
                    'packet': packet
                })
        except Exception as e:
            logging.error(f"处理数据包时出错: {str(e)}")

    def stop(self):
        """停止系统"""
        if self.running:
            logging.info("正在停止网络入侵检测系统...")
            self.capturer.stop_capture()
            self.running = False
            logging.info("系统已停止")

    def get_stats(self):
        """获取系统统计信息"""
        return self.analyzer.get_stats()

    def get_recent_alerts(self, limit=50):
        """获取最近的警报"""
        alerts = []
        try:
            conn = sqlite3.connect(self.config.db_file)
            c = conn.cursor()
            c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = c.fetchall()
            for row in rows:
                alerts.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'rule_id': row[2],
                    'rule_name': row[3],
                    'severity': row[4],
                    'src_ip': row[5],
                    'dst_ip': row[6],
                    'protocol': row[7],
                    'payload': row[8]
                })
            conn.close()
            logging.debug(f"从数据库获取到 {len(alerts)} 条警报记录")
        except Exception as e:
            logging.error(f"获取警报错误: {str(e)}")
        return alerts

    def toggle_test_mode(self, enable):
        """切换测试模式"""
        self.config.test_mode = enable
        if self.running:
            self.stop()
            # 添加短暂延迟确保完全停止
            time.sleep(0.5)
            self.start()
            logging.info(f"测试模式已{'启用' if enable else '禁用'}")

    def clear_alerts_database(self):
        """清除警报数据库"""
        try:
            conn = sqlite3.connect(self.config.db_file)
            c = conn.cursor()
            c.execute("DELETE FROM alerts")
            conn.commit()
            conn.close()
            logging.info("警报数据库已清除")
            # 重置警报计数
            self.analyzer.reset_alert_count()
            self.last_alert_count = 0
            return True
        except Exception as e:
            logging.error(f"清除数据库失败: {str(e)}")
            return False

    def debug_database(self):
        """调试数据库状态"""
        try:
            conn = sqlite3.connect(self.config.db_file)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = c.fetchall()

            c.execute("SELECT COUNT(*) FROM alerts")
            count = c.fetchone()[0]

            # 检查最近5条记录
            c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5")
            recent_alerts = c.fetchall()
            conn.close()

            return True, (
                f"数据库状态:\n"
                f"- 表: {tables}\n"
                f"- 警报记录数: {count}\n"
                f"- 最近5条警报: {recent_alerts}"
            )
        except Exception as e:
            return False, f"数据库错误: {str(e)}"


# ======================= Flask 应用 =======================

# 创建Flask应用
app = Flask(__name__)
# 使用threading模式替代eventlet
socketio = SocketIO(app, async_mode='threading')

# 全局配置和NIDS实例
config = Config()
nids = NetworkIDS(config)

# 登录状态管理
logged_in_users = {}


# 格式化时间持续
def format_duration(seconds):
    try:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
    except Exception as e:
        logging.error(f"格式化时间失败: {str(e)}")
        return "00:00:00"


# 生成协议分布数据
def generate_protocol_data(stats):
    protocols = stats['protocols']
    total = stats['packet_count']

    if total == 0:
        return []

    # 只显示占比超过1%的协议
    significant = {k: v for k, v in protocols.items() if v / total >= 0.01}
    other = total - sum(significant.values())

    data = [{'protocol': k, 'count': v, 'percentage': round(v / total * 100, 1)} for k, v in significant.items()]

    if other > 0:
        data.append({'protocol': '其他', 'count': other, 'percentage': round(other / total * 100, 1)})

    return data


# 生成流量来源数据
def generate_source_data(stats, limit=10):
    sources = stats['top_sources']
    sorted_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{'ip': ip, 'count': count} for ip, count in sorted_sources]


# 登录验证装饰器
def login_required(f):
    @functools.wraps(f)  # 保留原始函数名
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        if not session_id or session_id not in logged_in_users:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# 路由定义
@app.route('/')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, config=config, is_running=nids.running)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == config.web_username and password == config.web_password:
            # 生成会话ID
            session_id = hashlib.sha256(os.urandom(32)).hexdigest()
            logged_in_users[session_id] = time.time()

            response = redirect(url_for('dashboard'))
            response.set_cookie('session_id', session_id)
            return response
        else:
            flash('用户名或密码错误', 'danger')

    return render_template_string(LOGIN_HTML)


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id in logged_in_users:
        del logged_in_users[session_id]

    response = redirect(url_for('login'))
    response.set_cookie('session_id', '', expires=0)
    return response


@app.route('/alerts')
@login_required
def alerts_page():  # 修改函数名避免冲突
    alerts_list = nids.get_recent_alerts(100)
    return render_template_string(ALERTS_HTML, alerts=alerts_list, config=config, datetime=datetime)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():  # 修改函数名避免冲突
    if request.method == 'POST':
        # 更新网络设置
        config.interface = request.form.get('interface', config.interface)
        config.capture_filter = request.form.get('filter', config.capture_filter)

        # 更新警报设置
        config.email_enabled = 'email_enabled' in request.form
        config.smtp_server = request.form.get('smtp_server', config.smtp_server)
        config.smtp_port = int(request.form.get('smtp_port', config.smtp_port))
        config.smtp_user = request.form.get('smtp_user', config.smtp_user)
        config.smtp_password = request.form.get('smtp_password', config.smtp_password)
        config.to_emails = [e.strip() for e in request.form.get('to_emails', '').split(',')]

        # 更新测试模式
        config.test_mode = 'test_mode' in request.form
        nids.toggle_test_mode(config.test_mode)

        flash('设置已保存', 'success')

    return render_template_string(SETTINGS_HTML, config=config)


@app.route('/start_monitoring')
@login_required
def start_monitoring():
    if nids.start():
        return jsonify({'status': 'success', 'message': '监控已启动'})
    else:
        return jsonify({'status': 'error', 'message': '无法启动监控'})


@app.route('/stop_monitoring')
@login_required
def stop_monitoring():
    nids.stop()
    return jsonify({'status': 'success', 'message': '监控已停止'})


@app.route('/toggle_test_mode')
@login_required
def toggle_test_mode():
    enable = request.args.get('enable', 'true') == 'true'
    nids.toggle_test_mode(enable)
    return jsonify({'status': 'success', 'test_mode': enable})


@app.route('/clear_alerts')
@login_required
def clear_alerts():
    if nids.clear_alerts_database():
        return jsonify({'status': 'success', 'message': '警报已清除'})
    else:
        return jsonify({'status': 'error', 'message': '清除警报失败'})


@app.route('/get_stats')
@login_required
def get_stats():
    stats = nids.get_stats()

    # 格式化运行时间
    stats['uptime_str'] = format_duration(stats.get('uptime', 0))

    # 生成协议分布数据
    stats['protocol_data'] = generate_protocol_data(stats)

    # 生成流量来源数据
    stats['source_data'] = generate_source_data(stats)

    # 生成活动连接数据
    stats['connections'] = []
    if 'top_connections' in stats:
        for conn, count in stats['top_connections'][:5]:
            stats['connections'].append({
                'src_ip': conn[0],
                'dst_ip': conn[1],
                'protocol': conn[2],
                'count': count
            })

    return jsonify(stats)


@app.route('/get_recent_alerts')
@login_required
def get_recent_alerts():
    alerts_list = nids.get_recent_alerts(10)
    # 格式化时间
    for alert in alerts_list:
        alert['time_str'] = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')
    return jsonify(alerts_list)


@app.route('/export_alerts')
@login_required
def export_alerts():
    try:
        alerts_list = nids.get_recent_alerts(500)

        # 创建CSV内容
        csv_content = "时间,规则ID,规则名称,严重性,来源IP,目标IP,协议,负载\n"
        for alert in alerts_list:
            time_str = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            csv_content += f"{time_str},{alert['rule_id']},{alert['rule_name']},{alert['severity']},{alert['src_ip']},{alert['dst_ip']},{alert['protocol']},\"{alert['payload']}\"\n"

        # 创建响应
        response = Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=alerts_export.csv'}
        )
        return response
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/debug_database')
@login_required
def debug_database():
    success, message = nids.debug_database()
    if success:
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': message})


# SocketIO事件
@socketio.on('connect')
def handle_connect():
    logging.info('客户端已连接')


@socketio.on('disconnect')
def handle_disconnect():
    logging.info('客户端已断开连接')


# 定时发送统计更新
def send_stats_update():
    while True:
        if nids.running:
            stats = nids.get_stats()

            # 格式化运行时间
            stats['uptime_str'] = format_duration(stats.get('uptime', 0))

            # 生成协议分布数据
            stats['protocol_data'] = generate_protocol_data(stats)

            # 检查新警报
            current_alert_count = stats['alert_count']
            if current_alert_count > nids.last_alert_count:
                new_alerts = current_alert_count - nids.last_alert_count
                nids.last_alert_count = current_alert_count

                # 获取最新警报
                alerts_list = nids.get_recent_alerts(5)
                for alert in alerts_list:
                    alert['time_str'] = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')

                # 发送警报通知
                socketio.emit('new_alerts', {
                    'count': new_alerts,
                    'alerts': alerts_list
                })

            # 发送统计更新
            socketio.emit('stats_update', stats)

        time.sleep(2)


# 启动统计更新线程
stats_thread = threading.Thread(target=send_stats_update, daemon=True)
stats_thread.start()

# 主入口
if __name__ == '__main__':
    # 命令行参数解析
    parser = argparse.ArgumentParser(description='网络入侵检测系统 (Web版)')
    parser.add_argument('-i', '--interface', help='网络接口 (默认: eth0)')
    parser.add_argument('-f', '--filter', help='流量过滤规则 (默认: "tcp or udp")')
    parser.add_argument('-p', '--port', type=int, help='Web服务器端口 (默认: 5000)')
    parser.add_argument('-d', '--debug', help='启用调试模式', action='store_true')
    parser.add_argument('-t', '--test', help='启用测试模式', action='store_true')
    parser.add_argument('--username', help='Web登录用户名')
    parser.add_argument('--password', help='Web登录密码')
    args = parser.parse_args()

    # 配置系统
    if args.interface:
        config.interface = args.interface
    if args.filter:
        config.capture_filter = args.filter
    if args.port:
        config.web_port = args.port
    config.web_debug = args.debug
    config.test_mode = args.test
    if args.username:
        config.web_username = args.username
    if args.password:
        config.web_password = args.password

    # 确保日志目录存在
    os.makedirs(os.path.dirname(config.log_file), exist_ok=True)

    # 初始化日志
    log_level = logging.DEBUG if config.web_debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(config.log_file), logging.StreamHandler()]
    )

    # 设置Flapp密钥
    app.secret_key = config.web_secret_key

    # 启动Web服务器
    logging.info(f"启动Web服务器，访问地址: http://localhost:{config.web_port}")
    socketio.run(app, host='0.0.0.0', port=config.web_port, debug=config.web_debug)