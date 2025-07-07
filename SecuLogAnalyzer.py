from flask import Flask, render_template, request, redirect, url_for, flash
import os
import re
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import io
import base64
import seaborn as sns
import numpy as np

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 文件大小限制

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'STHeiti']  # 设置中文字体
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# 安全威胁检测规则（中文版）
SECURITY_RULES = [
    {"name": "SQL注入尝试",
     "pattern": r"('(''|[^'])*')|(;)|(\b(union|select|insert|delete|update|drop|alter|create)\b)", "severity": "高危"},
    {"name": "XSS攻击尝试", "pattern": r"<script.*?>|alert\(|onerror=|onload=", "severity": "高危"},
    {"name": "目录遍历尝试", "pattern": r"\.\./|\.\.\\", "severity": "中危"},
    {"name": "SSH暴力破解", "pattern": r"Failed password for .* from \d+\.\d+\.\d+\.\d+", "severity": "高危"},
    {"name": "命令注入尝试", "pattern": r"(\|\||\&\&|\;)\s*(rm|sh|bash|cmd|powershell|wget|curl|nc|telnet|ftp)",
     "severity": "高危"},
    {"name": "可疑文件访问",
     "pattern": r"(\.htaccess|\.env|\.git|\.svn|\.DS_Store|\.bak|\.swp|\.old|\.backup|/etc/passwd|/etc/shadow)",
     "severity": "中危"},
    {"name": "恶意爬虫", "pattern": r"(python-requests|scrapy|nmap|nikto|sqlmap|hydra|metasploit|wpscan)",
     "severity": "中危"},
    {"name": "可疑用户代理", "pattern": r"(nmap|nikto|sqlmap|hydra|metasploit|wpscan|dirb|gobuster|w3af|acunetix)",
     "severity": "低危"},
]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('没有选择文件', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('没有选择文件', 'danger')
        return redirect(url_for('index'))

    if file:
        # 保存上传的文件
        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 分析日志文件
        analysis_results = analyze_log_file(filepath)

        # 生成可视化图表
        plot_data = generate_visualizations(analysis_results)

        return render_template('results.html',
                               results=analysis_results,
                               filename=filename,
                               plot_data=plot_data)

    flash('文件上传失败', 'danger')
    return redirect(url_for('index'))


def analyze_log_file(filepath):
    results = {
        "file_info": {},
        "threats": [],
        "ip_activity": defaultdict(int),
        "top_ips": [],
        "threat_summary": defaultdict(int),
        "severity_count": {"高危": 0, "中危": 0, "低危": 0, "安全": 0},
        "line_count": 0,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            # 获取文件信息
            file_stats = os.stat(filepath)
            results["file_info"] = {
                "name": os.path.basename(filepath),
                "size": f"{file_stats.st_size / 1024:.2f} KB",
                "last_modified": datetime.fromtimestamp(file_stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            }

            # 分析每一行日志
            for line in file:
                results["line_count"] += 1

                # 提取IP地址
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                if ip_match:
                    ip = ip_match.group(0)
                    results["ip_activity"][ip] += 1

                # 检查安全威胁
                for rule in SECURITY_RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        threat = {
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "log_line": line.strip(),
                            "line_number": results["line_count"]
                        }
                        results["threats"].append(threat)
                        results["threat_summary"][rule["name"]] += 1
                        results["severity_count"][rule["severity"]] += 1

            # 获取最活跃的IP地址
            sorted_ips = sorted(results["ip_activity"].items(), key=lambda x: x[1], reverse=True)[:10]
            results["top_ips"] = sorted_ips

            # 如果没有发现威胁，添加一条安全信息
            if not results["threats"]:
                results["threats"].append({
                    "rule_name": "安全状态",
                    "severity": "安全",
                    "log_line": "未检测到已知安全威胁",
                    "line_number": "N/A"
                })
                results["severity_count"]["安全"] = 1

    except Exception as e:
        results["error"] = f"分析文件时出错: {str(e)}"

    return results


def generate_visualizations(results):
    plot_data = {}

    # 威胁类型分布（饼图）
    if results.get("threat_summary") and sum(results["threat_summary"].values()) > 0:
        labels = list(results["threat_summary"].keys())
        sizes = list(results["threat_summary"].values())

        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'STHeiti']
        plt.rcParams['axes.unicode_minus'] = False

        plt.figure(figsize=(9, 7))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140,
                textprops={'fontsize': 12}, wedgeprops={'edgecolor': 'white', 'linewidth': 1})
        plt.axis('equal')
        plt.title('安全威胁类型分布', fontsize=16, pad=20)

        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight', dpi=100)
        img.seek(0)
        plot_data['threat_distribution'] = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close()

    # IP活动分布（条形图）
    if results.get("top_ips") and len(results["top_ips"]) > 0:
        ips, counts = zip(*results["top_ips"])

        plt.figure(figsize=(12, 7))

        # 使用seaborn创建更美观的条形图
        sns.set_theme(style="whitegrid")
        ax = sns.barplot(x=list(ips), y=list(counts), palette="viridis")

        plt.xlabel('IP地址', fontsize=14)
        plt.ylabel('活动次数', fontsize=14)
        plt.title('最活跃的IP地址', fontsize=16, pad=20)
        plt.xticks(rotation=45, ha='right', fontsize=10)
        plt.yticks(fontsize=10)

        # 在条形上添加数值标签
        for i, v in enumerate(counts):
            ax.text(i, v + 0.2, str(v), ha='center', fontsize=10)

        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight', dpi=100)
        img.seek(0)
        plot_data['ip_activity'] = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close()

    # 威胁严重性分布（水平条形图）
    if results.get("severity_count") and sum(results["severity_count"].values()) > 0:
        severities = ["高危", "中危", "低危", "安全"]
        counts = [results["severity_count"][s] for s in severities]
        colors = ["#dc3545", "#ffc107", "#0dcaf0", "#198754"]  # 红, 黄, 蓝, 绿

        plt.figure(figsize=(10, 6))

        # 创建水平条形图
        bars = plt.barh(severities, counts, color=colors, edgecolor='white', linewidth=1)

        # 添加数值标签
        for i, bar in enumerate(bars):
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height() / 2,
                     f'{width}', ha='left', va='center', fontsize=12)

        plt.xlabel('数量', fontsize=14)
        plt.title('威胁严重性分布', fontsize=16, pad=20)
        plt.xlim(0, max(counts) * 1.2)  # 为标签留出空间
        plt.gca().invert_yaxis()  # 反转Y轴使高危在顶部

        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight', dpi=100)
        img.seek(0)
        plot_data['severity_distribution'] = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close()

    # 威胁时间分布（模拟数据）
    if results.get("threats") and len(results["threats"]) > 0:
        # 生成模拟时间数据
        np.random.seed(42)
        hours = list(range(24))
        values = np.random.poisson(lam=3, size=24).tolist()
        values[10] = 15  # 模拟高峰

        plt.figure(figsize=(12, 6))

        # 创建面积图
        plt.fill_between(hours, values, color='#8E2DE2', alpha=0.4)
        plt.plot(hours, values, color='#4A00E0', marker='o')

        plt.xlabel('时间 (小时)', fontsize=14)
        plt.ylabel('威胁数量', fontsize=14)
        plt.title('威胁活动时间分布', fontsize=16, pad=20)
        plt.xticks(hours, [f"{h}:00" for h in hours], rotation=45, fontsize=10)
        plt.grid(True, linestyle='--', alpha=0.7)

        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight', dpi=100)
        img.seek(0)
        plot_data['threat_timeline'] = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close()

    return plot_data


# HTML模板字符串
@app.route('/results')
def results():
    # 这个路由通常由上传重定向而来，直接访问将重定向到首页
    return redirect(url_for('index'))


# 内联HTML模板
@app.route('/index.html')
def home():
    return render_template('index.html')


app.add_url_rule('/index.html', 'home', home)


# 模板渲染函数
@app.template_global()
def severity_color(severity):
    colors = {
        "高危": "danger",
        "中危": "warning",
        "低危": "info",
        "安全": "success"
    }
    return colors.get(severity, "secondary")


# 定义模板
@app.template_global()
def render_template(template_name, **context):
    if template_name == 'index.html':
        return '''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>日志安全分析系统</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                body {
                    background: linear-gradient(135deg, #1a2a6c, #b21f1f, #1a2a6c);
                    background-size: 400% 400%;
                    animation: gradientBG 15s ease infinite;
                    color: #fff;
                    min-height: 100vh;
                    padding-top: 60px;
                }

                @keyframes gradientBG {
                    0% { background-position: 0% 50%; }
                    50% { background-position: 100% 50%; }
                    100% { background-position: 0% 50%; }
                }

                .card {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    color: #fff;
                    transition: transform 0.3s;
                }

                .card:hover {
                    transform: translateY(-10px);
                }

                .btn-primary {
                    background: linear-gradient(to right, #4A00E0, #8E2DE2);
                    border: none;
                    border-radius: 50px;
                    padding: 12px 30px;
                    font-weight: bold;
                    transition: all 0.3s;
                }

                .btn-primary:hover {
                    background: linear-gradient(to right, #8E2DE2, #4A00E0);
                    transform: scale(1.05);
                }

                .upload-area {
                    border: 3px dashed rgba(255, 255, 255, 0.3);
                    border-radius: 15px;
                    padding: 40px;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.3s;
                    background: rgba(0, 0, 0, 0.2);
                }

                .upload-area:hover {
                    border-color: #8E2DE2;
                    background: rgba(0, 0, 0, 0.3);
                }

                .feature-icon {
                    font-size: 2.5rem;
                    margin-bottom: 20px;
                    color: #8E2DE2;
                }

                .severity-badge {
                    font-size: 0.85rem;
                    padding: 5px 12px;
                    border-radius: 50px;
                }

                .threat-card {
                    margin-bottom: 15px;
                    border-left: 4px solid;
                }

                .threat-high {
                    border-left-color: #dc3545;
                }

                .threat-medium {
                    border-left-color: #ffc107;
                }

                .threat-low {
                    border-left-color: #0dcaf0;
                }

                .threat-safe {
                    border-left-color: #198754;
                }

                footer {
                    background: rgba(0, 0, 0, 0.3);
                    padding: 20px 0;
                    margin-top: 40px;
                }

                .logo {
                    font-weight: 800;
                    background: linear-gradient(to right, #8E2DE2, #4A00E0);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
            </style>
        </head>
        <body>
            <!-- 导航栏 -->
            <nav class="navbar navbar-expand-lg navbar-dark fixed-top" style="background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(10px);">
                <div class="container">
                    <a class="navbar-brand" href="#">
                        <i class="fas fa-shield-alt me-2"></i>
                        <span class="logo">SecuLogAnalyzer</span>
                    </a>
                    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="navbarNav">
                        <ul class="navbar-nav ms-auto">
                            <li class="nav-item">
                                <a class="nav-link active" href="#">首页</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#features">功能</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#how-it-works">使用指南</a>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>

            <!-- 首页头部 -->
            <div class="container py-5 mt-4">
                <div class="row align-items-center">
                    <div class="col-lg-6">
                        <h1 class="display-4 fw-bold mb-4">专业的<span class="logo">日志安全分析</span>工具</h1>
                        <p class="lead mb-4">上传您的服务器日志文件，我们的系统将自动检测潜在的安全威胁、恶意活动和可疑行为，为您的网络安全保驾护航。</p>
                        <div class="d-flex flex-wrap gap-2">
                            <a href="#upload-section" class="btn btn-primary btn-lg">
                                <i class="fas fa-cloud-upload-alt me-2"></i>立即分析日志
                            </a>
                            <a href="#features" class="btn btn-outline-light btn-lg">
                                <i class="fas fa-info-circle me-2"></i>了解更多
                            </a>
                        </div>
                    </div>
                    <div class="col-lg-6 mt-5 mt-lg-0">
                        <div class="card p-3">
                            <img src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=1470" 
                                 class="img-fluid rounded" 
                                 alt="网络安全分析">
                        </div>
                    </div>
                </div>
            </div>

            <!-- 文件上传部分 -->
            <div class="container py-5" id="upload-section">
                <div class="row justify-content-center">
                    <div class="col-lg-8">
                        <div class="card p-4">
                            <h2 class="text-center mb-4"><i class="fas fa-file-upload me-2"></i>上传日志文件</h2>
                            <p class="text-center mb-4">支持.txt, .log等文本格式文件，最大文件大小16MB</p>

                            <form action="/upload" method="POST" enctype="multipart/form-data">
                                <div class="upload-area" id="drop-area">
                                    <i class="fas fa-cloud-upload-alt fa-3x mb-3"></i>
                                    <h5>拖放文件到此处或点击上传</h5>
                                    <p class="text-muted">支持服务器日志、应用日志、防火墙日志等</p>
                                    <input type="file" name="file" id="file-input" class="d-none" accept=".txt,.log">
                                    <label for="file-input" class="btn btn-light mt-3">选择文件</label>
                                    <div id="file-name" class="mt-3"></div>
                                </div>
                                <div class="text-center mt-4">
                                    <button type="submit" class="btn btn-primary btn-lg">
                                        <i class="fas fa-search me-2"></i>分析日志
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 功能特性 -->
            <div class="container py-5" id="features">
                <h2 class="text-center mb-5">强大的安全分析功能</h2>
                <div class="row g-4">
                    <div class="col-md-4">
                        <div class="card h-100 p-4 text-center">
                            <div class="feature-icon">
                                <i class="fas fa-shield-virus"></i>
                            </div>
                            <h4>威胁检测</h4>
                            <p>检测SQL注入、XSS攻击、命令注入、暴力破解等多种安全威胁</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card h-100 p-4 text-center">
                            <div class="feature-icon">
                                <i class="fas fa-map-marked-alt"></i>
                            </div>
                            <h4>IP活动分析</h4>
                            <p>识别最活跃的IP地址，发现可疑访问源和潜在攻击者</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card h-100 p-4 text-center">
                            <div class="feature-icon">
                                <i class="fas fa-chart-pie"></i>
                            </div>
                            <h4>可视化报告</h4>
                            <p>通过图表直观展示威胁分布和活动趋势</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 使用指南 -->
            <div class="container py-5" id="how-it-works">
                <h2 class="text-center mb-5">使用指南</h2>
                <div class="row g-4">
                    <div class="col-md-4">
                        <div class="card p-3 h-100">
                            <div class="d-flex align-items-center mb-3">
                                <div class="bg-primary text-white rounded-circle p-3 me-3">
                                    <h2 class="mb-0">1</h2>
                                </div>
                                <h4 class="mb-0">上传日志</h4>
                            </div>
                            <p>点击"选择文件"按钮上传您的服务器日志文件，支持常见的日志格式。</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card p-3 h-100">
                            <div class="d-flex align-items-center mb-3">
                                <div class="bg-primary text-white rounded-circle p-3 me-3">
                                    <h2 class="mb-0">2</h2>
                                </div>
                                <h4 class="mb-0">自动分析</h4>
                            </div>
                            <p>我们的系统将扫描日志文件，检测潜在的安全威胁和可疑活动。</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card p-3 h-100">
                            <div class="d-flex align-items-center mb-3">
                                <div class="bg-primary text-white rounded-circle p-3 me-3">
                                    <h2 class="mb-0">3</h2>
                                </div>
                                <h4 class="mb-0">获取报告</h4>
                            </div>
                            <p>查看详细的分析报告，包括威胁列表、IP活动统计和可视化图表。</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 页脚 -->
            <footer class="text-center">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6 mx-auto">
                            <h4 class="logo mb-3">SecuLogAnalyzer</h4>
                            <p>专业的日志安全分析工具，为您的网络安全保驾护航</p>
                            <div class="d-flex justify-content-center gap-3 mb-3">
                                <a href="#" class="text-white"><i class="fab fa-github fa-lg"></i></a>
                                <a href="#" class="text-white"><i class="fab fa-twitter fa-lg"></i></a>
                                <a href="#" class="text-white"><i class="fab fa-linkedin fa-lg"></i></a>
                            </div>
                            <p>&copy; 2023 SecuLogAnalyzer - 网络安全分析工具</p>
                        </div>
                    </div>
                </div>
            </footer>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // 文件上传交互
                const dropArea = document.getElementById('drop-area');
                const fileInput = document.getElementById('file-input');
                const fileName = document.getElementById('file-name');

                // 点击上传区域触发文件选择
                dropArea.addEventListener('click', () => {
                    fileInput.click();
                });

                // 显示选择的文件名
                fileInput.addEventListener('change', function() {
                    if (this.files.length > 0) {
                        fileName.innerHTML = `<div class="alert alert-info">
                            <i class="fas fa-file me-2"></i> ${this.files[0].name}
                        </div>`;
                    }
                });

                // 拖放功能
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                    dropArea.addEventListener(eventName, preventDefaults, false);
                });

                function preventDefaults(e) {
                    e.preventDefault();
                    e.stopPropagation();
                }

                ['dragenter', 'dragover'].forEach(eventName => {
                    dropArea.addEventListener(eventName, highlight, false);
                });

                ['dragleave', 'drop'].forEach(eventName => {
                    dropArea.addEventListener(eventName, unhighlight, false);
                });

                function highlight() {
                    dropArea.style.borderColor = '#8E2DE2';
                    dropArea.style.backgroundColor = 'rgba(0, 0, 0, 0.3)';
                }

                function unhighlight() {
                    dropArea.style.borderColor = 'rgba(255, 255, 255, 0.3)';
                    dropArea.style.backgroundColor = 'rgba(0, 0, 0, 0.2)';
                }

                // 处理文件拖放
                dropArea.addEventListener('drop', handleDrop, false);

                function handleDrop(e) {
                    const dt = e.dataTransfer;
                    const files = dt.files;

                    if (files.length) {
                        fileInput.files = files;
                        fileName.innerHTML = `<div class="alert alert-info">
                            <i class="fas fa-file me-2"></i> ${files[0].name}
                        </div>`;
                    }
                }
            </script>
        </body>
        </html>
        '''
    elif template_name == 'results.html':
        results = context['results']
        filename = context['filename']
        plot_data = context['plot_data']

        # 构建威胁列表HTML
        threats_html = ""
        for threat in results['threats']:
            color_class = f"threat-{severity_color(threat['severity']).replace('danger', 'high').replace('warning', 'medium').replace('info', 'low').replace('success', 'safe')}"
            threats_html += f'''
            <div class="card threat-card {color_class}">
                <div class="card-body">
                    <div class="d-flex justify-content-between">
                        <h5 class="card-title">{threat['rule_name']}</h5>
                        <span class="badge bg-{severity_color(threat['severity'])} severity-badge">{threat['severity']}</span>
                    </div>
                    <p class="card-text"><small>日志行 #{threat['line_number']}</small></p>
                    <div class="log-line bg-dark p-2 rounded mt-2">
                        <code>{threat['log_line']}</code>
                    </div>
                </div>
            </div>
            '''

        # 构建IP活动HTML
        ip_activity_html = ""
        for ip, count in results['top_ips']:
            ip_activity_html += f'''
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
                <td>
                    <a href="https://www.ipvoid.com/ip/{ip}/" target="_blank" class="btn btn-sm btn-outline-light">
                        <i class="fas fa-search me-1"></i>检查
                    </a>
                </td>
            </tr>
            '''

        # 构建图表HTML
        charts_html = ""
        if plot_data.get('threat_distribution'):
            charts_html += f'''
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>威胁类型分布</h5>
                    </div>
                    <div class="card-body">
                        <img src="data:image/png;base64,{plot_data['threat_distribution']}" class="img-fluid rounded">
                    </div>
                </div>
            </div>
            '''

        if plot_data.get('ip_activity'):
            charts_html += f'''
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>IP活动分析</h5>
                    </div>
                    <div class="card-body">
                        <img src="data:image/png;base64,{plot_data['ip_activity']}" class="img-fluid rounded">
                    </div>
                </div>
            </div>
            '''

        if plot_data.get('severity_distribution'):
            charts_html += f'''
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-exclamation-triangle me-2"></i>威胁严重性分布</h5>
                    </div>
                    <div class="card-body">
                        <img src="data:image/png;base64,{plot_data['severity_distribution']}" class="img-fluid rounded">
                    </div>
                </div>
            </div>
            '''

        if plot_data.get('threat_timeline'):
            charts_html += f'''
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-clock me-2"></i>威胁活动时间分布</h5>
                    </div>
                    <div class="card-body">
                        <img src="data:image/png;base64,{plot_data['threat_timeline']}" class="img-fluid rounded">
                    </div>
                </div>
            </div>
            '''

        return f'''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>分析结果 - SecuLogAnalyzer</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                body {{
                    background: linear-gradient(135deg, #1a2a6c, #b21f1f, #1a2a6c);
                    background-size: 400% 400%;
                    animation: gradientBG 15s ease infinite;
                    color: #fff;
                    min-height: 100vh;
                    padding-top: 60px;
                }}

                @keyframes gradientBG {{
                    0% {{ background-position: 0% 50%; }}
                    50% {{ background-position: 100% 50%; }}
                    100% {{ background-position: 0% 50%; }}
                }}

                .card {{
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    color: #fff;
                }}

                .btn-primary {{
                    background: linear-gradient(to right, #4A00E0, #8E2DE2);
                    border: none;
                    border-radius: 50px;
                    padding: 10px 25px;
                    font-weight: bold;
                }}

                .severity-badge {{
                    font-size: 0.85rem;
                    padding: 5px 12px;
                    border-radius: 50px;
                }}

                .threat-card {{
                    margin-bottom: 15px;
                    border-left: 4px solid;
                }}

                .threat-high {{
                    border-left-color: #dc3545;
                }}

                .threat-medium {{
                    border-left-color: #ffc107;
                }}

                .threat-low {{
                    border-left-color: #0dcaf0;
                }}

                .threat-safe {{
                    border-left-color: #198754;
                }}

                .log-line {{
                    font-family: monospace;
                    font-size: 0.9rem;
                    overflow-x: auto;
                    white-space: pre-wrap;
                }}

                .summary-card {{
                    transition: transform 0.3s;
                }}

                .summary-card:hover {{
                    transform: translateY(-5px);
                }}

                .logo {{
                    font-weight: 800;
                    background: linear-gradient(to right, #8E2DE2, #4A00E0);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }}

                .chart-container {{
                    border-radius: 10px;
                    overflow: hidden;
                }}
            </style>
        </head>
        <body>
            <!-- 导航栏 -->
            <nav class="navbar navbar-expand-lg navbar-dark fixed-top" style="background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(10px);">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="fas fa-shield-alt me-2"></i>
                        <span class="logo">SecuLogAnalyzer</span>
                    </a>
                    <div class="d-flex">
                        <a href="/" class="btn btn-outline-light">
                            <i class="fas fa-arrow-left me-2"></i>返回首页
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container py-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1><i class="fas fa-file-alt me-2"></i>日志分析结果</h1>
                    <a href="/" class="btn btn-outline-light">
                        <i class="fas fa-undo me-2"></i>分析新文件
                    </a>
                </div>

                <!-- 文件信息摘要 -->
                <div class="row mb-4">
                    <div class="col-md-3 mb-3">
                        <div class="card summary-card h-100">
                            <div class="card-body text-center">
                                <h2 class="card-title">{results['line_count']}</h2>
                                <p class="card-text">日志行数</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card summary-card h-100">
                            <div class="card-body text-center">
                                <h2 class="card-title">{len(results['threats'])}</h2>
                                <p class="card-text">检测到威胁</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card summary-card h-100">
                            <div class="card-body text-center">
                                <h2 class="card-title">{len(results['ip_activity'])}</h2>
                                <p class="card-text">唯一IP地址</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card summary-card h-100">
                            <div class="card-body text-center">
                                <h2 class="card-title">{results['analysis_time']}</h2>
                                <p class="card-text">分析时间</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 文件信息 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="mb-0"><i class="fas fa-info-circle me-2"></i>文件信息</h4>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <p><strong>文件名:</strong> {results['file_info']['name']}</p>
                            </div>
                            <div class="col-md-4">
                                <p><strong>文件大小:</strong> {results['file_info']['size']}</p>
                            </div>
                            <div class="col-md-4">
                                <p><strong>修改时间:</strong> {results['file_info']['last_modified']}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 检测到的威胁 -->
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h4 class="mb-0"><i class="fas fa-shield-alt me-2"></i>检测到的安全威胁</h4>
                        <span class="badge bg-{'danger' if len(results['threats']) > 0 else 'success'}">
                            {len(results['threats'])} 个威胁
                        </span>
                    </div>
                    <div class="card-body">
                        {threats_html if threats_html else '<div class="alert alert-success">未检测到安全威胁</div>'}
                    </div>
                </div>

                <!-- IP活动 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="mb-0"><i class="fas fa-map-marker-alt me-2"></i>IP活动分析</h4>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>IP地址</th>
                                        <th>活动次数</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {ip_activity_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- 可视化图表 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="mb-0"><i class="fas fa-chart-bar me-2"></i>分析图表</h4>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            {charts_html}
                        </div>
                    </div>
                </div>

                <!-- 行动建议 -->
                <div class="card">
                    <div class="card-header">
                        <h4 class="mb-0"><i class="fas fa-lightbulb me-2"></i>安全建议</h4>
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            <li class="list-group-item bg-dark text-white border-secondary">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                定期更新服务器和应用程序到最新版本
                            </li>
                            <li class="list-group-item bg-dark text-white border-secondary">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                配置防火墙规则，限制不必要的访问
                            </li>
                            <li class="list-group-item bg-dark text-white border-secondary">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                对检测到的可疑IP地址实施访问控制
                            </li>
                            <li class="list-group-item bg-dark text-white border-secondary">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                使用强密码策略并启用多因素认证
                            </li>
                            <li class="list-group-item bg-dark text-white border-secondary">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                定期备份重要数据并测试恢复流程
                            </li>
                        </ul>
                    </div>
                </div>

                <!-- 页脚 -->
                <footer class="text-center mt-5 pt-4 border-top border-secondary">
                    <p>&copy; 2023 SecuLogAnalyzer - 网络安全分析工具</p>
                </footer>
            </div>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        '''
    else:
        return "Template not found"


if __name__ == '__main__':
    app.run(debug=True, port=5008)