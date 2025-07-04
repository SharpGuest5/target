import os
import re
import time
import zipfile
import tempfile
import shutil
from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'


# 添加上下文处理器
@app.context_processor
def inject_now():
    return {'now': datetime.now()}


# 代码审计安全规则
CODE_AUDIT_RULES = [
    {
        "id": "sql-injection",
        "name": "SQL注入漏洞",
        "severity": "高危",
        "description": "检测到未参数化的SQL查询，可能导致SQL注入攻击",
        "patterns": [
            r"execute\(.*?\+\s*\w+\)",
            r"cursor\.execute\(.*?\%s\)",
            r"query\s*=\s*.+?\+\s*\w+",
            r"db\.query\(.*?\+\s*\w+\)"
        ],
        "languages": ["python", "php", "java", "javascript"],
        "example": {
            "bad": "# SQL注入漏洞示例\nusername = request.GET.get('username')\nquery = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\ncursor.execute(query)",
            "good": "# 使用参数化查询\nusername = request.GET.get('username')\nquery = \"SELECT * FROM users WHERE username = %s\"\ncursor.execute(query, (username,))"
        },
        "recommendations": [
            "始终使用参数化查询或预编译语句",
            "避免直接拼接用户输入到SQL语句中",
            "使用ORM框架进行数据库操作",
            "对用户输入进行严格的验证和过滤"
        ]
    },
    {
        "id": "xss",
        "name": "跨站脚本攻击(XSS)",
        "severity": "高危",
        "description": "检测到未转义的用户输入直接输出到HTML，可能导致XSS攻击",
        "patterns": [
            r"innerHTML\s*=\s*.+",
            r"document\.write\(.*?\+\s*\w+\)",
            r"response\.write\(.*?\+\s*\w+\)",
            r"echo\s+.+?\..+?;",
            r"print\s+.+?\..+?;"
        ],
        "languages": ["javascript", "php", "python", "html"],
        "example": {
            "bad": "// XSS漏洞示例\nconst userInput = document.getElementById('input').value;\ndocument.getElementById('output').innerHTML = userInput;",
            "good": "// 使用textContent避免XSS\nconst userInput = document.getElementById('input').value;\ndocument.getElementById('output').textContent = userInput;"
        },
        "recommendations": [
            "对所有用户输入进行HTML转义",
            "使用textContent代替innerHTML",
            "设置Content Security Policy (CSP)",
            "使用安全的框架如React/Vue的自动转义功能"
        ]
    },
    {
        "id": "command-injection",
        "name": "命令注入漏洞",
        "severity": "高危",
        "description": "检测到使用用户输入直接构造系统命令，可能导致命令注入",
        "patterns": [
            r"os\.system\(.*?\+\s*\w+\)",
            r"subprocess\.call\(.*?\+\s*\w+\)",
            r"exec\(.*?\+\s*\w+\)",
            r"Runtime\.getRuntime\(\)\.exec\(.*?\+\s*\w+\)"
        ],
        "languages": ["python", "java", "php"],
        "example": {
            "bad": "# 命令注入漏洞示例\nfilename = request.POST.get('filename')\nos.system(\"cat \" + filename)",
            "good": "# 使用安全API替代\nfilename = request.POST.get('filename')\nwith open(filename, 'r') as f:\n    content = f.read()"
        },
        "recommendations": [
            "避免使用shell命令执行用户输入",
            "使用语言内置的安全API替代系统命令",
            "如果需要执行命令，使用白名单验证输入",
            "使用最小权限运行应用程序"
        ]
    },
    {
        "id": "hardcoded-secret",
        "name": "硬编码密钥",
        "severity": "中危",
        "description": "检测到硬编码的密码、API密钥或其他敏感信息",
        "patterns": [
            r"password\s*=\s*['\"].{8,}['\"]",
            r"api_key\s*=\s*['\"].{10,}['\"]",
            r"secret\s*=\s*['\"].{8,}['\"]",
            r"token\s*=\s*['\"].{10,}['\"]"
        ],
        "languages": ["python", "java", "javascript", "php", "ruby"],
        "example": {
            "bad": "# 硬编码密钥示例\nAPI_KEY = \"sk_live_1234567890abcdef\"\ndb_password = \"P@ssw0rd123\"",
            "good": "# 从环境变量获取密钥\nimport os\nAPI_KEY = os.getenv(\"API_KEY\")\ndb_password = os.getenv(\"DB_PASSWORD\")"
        },
        "recommendations": [
            "永远不要在代码中硬编码敏感信息",
            "使用环境变量或密钥管理服务",
            "使用配置文件并确保其不被提交到版本控制",
            "定期轮换密钥和密码"
        ]
    },
    {
        "id": "insecure-deserialization",
        "name": "不安全的反序列化",
        "severity": "高危",
        "description": "检测到可能不安全的反序列化操作",
        "patterns": [
            r"pickle\.loads\(",
            r"new\s+ObjectInputStream\(",
            r"unserialize\(",
            r"JSON\.parse\("
        ],
        "languages": ["python", "java", "php", "javascript"],
        "example": {
            "bad": "# 不安全的反序列化示例\nimport pickle\ndata = request.data\nobj = pickle.loads(data)",
            "good": "# 使用安全的序列化格式\nimport json\ndata = request.data\nobj = json.loads(data)"
        },
        "recommendations": [
            "避免反序列化不受信任的数据",
            "使用JSON等安全的序列化格式",
            "实现签名验证确保数据完整性",
            "在沙箱环境中执行反序列化操作"
        ]
    },
    {
        "id": "path-traversal",
        "name": "路径遍历漏洞",
        "severity": "中危",
        "description": "检测到使用用户输入构造文件路径，可能导致路径遍历攻击",
        "patterns": [
            r"open\(.*?\+\s*\w+\)",
            r"new\s+File\(.*?\+\s*\w+\)",
            r"fopen\(.*?\+\s*\w+\)",
            r"File\.ReadAllText\(.*?\+\s*\w+\)"
        ],
        "languages": ["python", "java", "php", "csharp"],
        "example": {
            "bad": "# 路径遍历漏洞示例\nfilename = request.args.get('file')\nwith open('/var/www/uploads/' + filename, 'r') as f:",
            "good": "# 使用安全路径处理\nfrom pathlib import Path\nbase = Path('/var/www/uploads')\nfilename = request.args.get('file')\nfilepath = base / filename\nif base not in filepath.parents:\n    raise Exception('Invalid path')\nwith open(filepath, 'r') as f:"
        },
        "recommendations": [
            "验证用户输入的文件路径",
            "使用绝对路径并检查是否在允许的目录内",
            "规范化路径并检查路径遍历序列",
            "使用安全的文件API"
        ]
    },
    {
        "id": "ssrf",
        "name": "服务器端请求伪造(SSRF)",
        "severity": "高危",
        "description": "检测到使用用户输入构造URL请求，可能导致SSRF攻击",
        "patterns": [
            r"requests\.get\(.*?\+\s*\w+\)",
            r"HttpClient\.execute\(.*?\+\s*\w+\)",
            r"curl_init\(.*?\+\s*\w+\)",
            r"WebClient\.DownloadData\(.*?\+\s*\w+\)"
        ],
        "languages": ["python", "java", "php", "csharp"],
        "example": {
            "bad": "# SSRF漏洞示例\nurl = request.GET.get('url')\nresponse = requests.get(url)",
            "good": "# 使用白名单验证URL\nallowed_domains = ['example.com', 'api.example.com']\nurl = request.GET.get('url')\nparsed = urlparse(url)\nif parsed.hostname not in allowed_domains:\n    raise Exception('Invalid domain')\nresponse = requests.get(url)"
        },
        "recommendations": [
            "验证用户提供的URL",
            "使用白名单限制可访问的域名",
            "避免请求内部网络资源",
            "使用网络层防护限制出站连接"
        ]
    }
]


# 代码审计函数
def audit_code(file_path, file_name):
    """审计上传的代码文件"""
    results = []

    # 获取文件扩展名
    ext = os.path.splitext(file_name)[1].lower()

    # 根据扩展名确定语言
    language = ""
    if ext in ['.py']:
        language = "python"
    elif ext in ['.js', '.jsx']:
        language = "javascript"
    elif ext in ['.java']:
        language = "java"
    elif ext in ['.php']:
        language = "php"
    elif ext in ['.html', '.htm']:
        language = "html"
    elif ext in ['.cs']:
        language = "csharp"
    elif ext in ['.rb']:
        language = "ruby"
    else:
        return [{
            "file": file_name,
            "vulnerable": False,
            "message": "不支持的文件类型",
            "details": []
        }]

    # 读取文件内容
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return [{
            "file": file_name,
            "vulnerable": False,
            "message": f"读取文件失败: {str(e)}",
            "details": []
        }]

    # 应用所有规则进行检测
    vulnerabilities = []
    for rule in CODE_AUDIT_RULES:
        if language not in rule["languages"]:
            continue

        for pattern in rule["patterns"]:
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    # 获取上下文
                    start_line = max(0, content.count('\n', 0, match.start()) - 1)
                    lines = content.split('\n')
                    context = lines[start_line:start_line + 3] if start_line + 3 < len(lines) else lines[start_line:]

                    vulnerabilities.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "line": start_line + 1,
                        "match": match.group(0),
                        "context": context
                    })
            except Exception as e:
                app.logger.error(f"规则匹配失败: {rule['id']} - {str(e)}")

    # 返回结果
    return [{
        "file": file_name,
        "vulnerable": len(vulnerabilities) > 0,
        "message": f"检测到 {len(vulnerabilities)} 个潜在漏洞" if vulnerabilities else "未检测到漏洞",
        "details": vulnerabilities
    }]


# 首页路由
@app.route('/')
def index():
    """首页"""
    return render_template('index.html', rules=CODE_AUDIT_RULES)


# 代码审计路由
@app.route('/audit', methods=['POST'])
def perform_code_audit():
    """执行代码审计"""
    if 'file' not in request.files:
        flash('未选择文件', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('未选择文件', 'danger')
        return redirect(url_for('index'))

    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    results = []

    try:
        # 保存上传的文件
        file_path = os.path.join(temp_dir, file.filename)
        file.save(file_path)

        # 检查是否为ZIP文件
        if file.filename.lower().endswith('.zip'):
            # 解压ZIP文件
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                os.remove(file_path)  # 删除上传的ZIP文件

                # 遍历解压后的文件
                for root, dirs, files in os.walk(temp_dir):
                    for name in files:
                        full_path = os.path.join(root, name)
                        rel_path = os.path.relpath(full_path, temp_dir)
                        file_results = audit_code(full_path, rel_path)
                        results.extend(file_results)
        else:
            # 单个文件审计
            results = audit_code(file_path, file.filename)

        # 计算统计信息
        total_files = len(results)
        vulnerable_files = sum(1 for r in results if r['vulnerable'])
        total_vulnerabilities = sum(len(r['details']) for r in results)

        # 按严重程度统计
        severity_count = {"高危": 0, "中危": 0, "低危": 0}
        for result in results:
            for vuln in result['details']:
                severity_count[vuln['severity']] += 1

        return render_template('results.html',
                               results=results,
                               total_files=total_files,
                               vulnerable_files=vulnerable_files,
                               total_vulnerabilities=total_vulnerabilities,
                               severity_count=severity_count)

    except Exception as e:
        app.logger.error(f"代码审计失败: {str(e)}")
        flash(f'代码审计失败: {str(e)}', 'danger')
        return redirect(url_for('index'))

    finally:
        # 清理临时目录
        try:
            shutil.rmtree(temp_dir)
        except:
            pass


# 漏洞修复建议
@app.route('/fix/<rule_id>')
def code_fix(rule_id):
    """显示漏洞修复建议"""
    rule = next((r for r in CODE_AUDIT_RULES if r['id'] == rule_id), None)

    if not rule:
        flash('未找到指定的规则', 'danger')
        return redirect(url_for('index'))

    return render_template('fix.html', rule=rule)


# 添加 404 错误处理器
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# 创建 templates 目录并添加基本模板
def ensure_template_directory():
    """确保模板目录存在并创建基本模板文件"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)

    # 创建 index.html
    index_path = os.path.join(templates_dir, 'index.html')
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代码安全审计系统 - CodeAudit Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #e94560;
            --warning: #ff9a3c;
            --success: #0f9d58;
            --info: #4285f4;
            --text-light: #f0f0f0;
            --text-dark: #333;
            --card-bg: rgba(255, 255, 255, 0.08);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text-light);
            min-height: 100vh;
            background-attachment: fixed;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(10, 10, 20, 0.85);
            backdrop-filter: blur(10px);
            padding: 15px 0;
            border-bottom: 1px solid rgba(233, 69, 96, 0.3);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 1.8rem;
            color: var(--text-light);
            text-decoration: none;
        }

        .logo-icon {
            color: var(--accent);
            font-size: 2rem;
        }

        .hero {
            padding: 80px 0 50px;
            text-align: center;
            max-width: 800px;
            margin: 0 auto;
        }

        .hero h1 {
            font-size: 3.2rem;
            margin-bottom: 20px;
            font-weight: 700;
            background: linear-gradient(45deg, var(--accent), var(--warning));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            font-family: 'Orbitron', sans-serif;
        }

        .hero p {
            font-size: 1.3rem;
            opacity: 0.85;
            margin-bottom: 40px;
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            border-color: rgba(233, 69, 96, 0.4);
        }

        .card-title {
            font-size: 1.6rem;
            margin-bottom: 20px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .form-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
        }

        .upload-area {
            border: 2px dashed rgba(255, 255, 255, 0.3);
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            transition: var(--transition);
            cursor: pointer;
        }

        .upload-area:hover {
            border-color: var(--accent);
            background: rgba(233, 69, 96, 0.05);
        }

        .upload-icon {
            font-size: 3rem;
            margin-bottom: 15px;
            color: var(--info);
        }

        .supported-files {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
        }

        .file-types {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
            margin-top: 10px;
        }

        .file-type {
            background: rgba(66, 133, 244, 0.2);
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9rem;
        }

        .btn {
            display: inline-block;
            background: var(--accent);
            color: white;
            border: none;
            padding: 14px 30px;
            font-size: 1.1rem;
            font-weight: 500;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
        }

        .btn:hover {
            background: #ff2e4f;
            transform: translateY(-3px);
            box-shadow: 0 7极 15px rgba(233, 69, 96, 0.3);
        }

        .btn-block {
            display: block;
            width: 100%;
        }

        .rule-card {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 3px solid var(--accent);
        }

        .rule-card.medium {
            border-left-color: var(--warning);
        }

        .rule-card.low {
            border-left-color: var(--info);
        }

        .rule-card h3 {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .severity-high {
            background: var(--accent);
        }

        .severity-medium {
            background: var(--warning);
        }

        .severity-low {
            background: var(--info);
        }

        footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 60px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: rgba(255, 255, 255, 0.6);
        }

        .alert {
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .alert-danger {
            background: rgba(233, 69, 96, 0.2);
            border: 1px solid var(--accent);
        }

        .alert-warning {
            background: rgba(255, 154, 60, 0.2);
            border: 1px solid var(--warning);
        }

        .alert-success {
            background: rgba(15, 157, 88, 0.2);
            border: 1px solid var(--success);
        }

        .feature-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }

        .feature-card {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
        }

        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            border-color: var(--accent);
        }

        .feature-icon {
            font-size: 3rem;
            margin-bottom: 20px;
            color: var(--info);
        }

        /* Responsive styles */
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2.5rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="navbar">
                <a href="/" class="logo">
                    <span class="logo-icon">🔍</span>
                    <span>CodeAudit Pro</span>
                </a>
            </div>
        </div>
    </header>

    <main class="container">
        <div class="hero">
            <h1>代码安全审计系统</h1>
            <p>深度分析您的源代码，发现潜在安全漏洞，提升应用安全性</p>
        </div>

        <div class="card">
            <h2 class="card-title">上传代码进行安全分析</h2>

            <form action="/audit" method="post" enctype="multipart/form-data">
                <div class="upload-area" id="upload-area">
                    <div class="upload-icon">📁</div>
                    <h3>点击或拖拽文件到此处上传</h3>
                    <p>支持单个文件或ZIP压缩包</p>

                    <div class="supported-files">
                        <p>支持的文件类型:</p>
                        <div class="file-types">
                            <span class="file-type">.py (Python)</span>
                            <span class="file-type">.js (JavaScript)</span>
                            <span class="file-type">.java (Java)</span>
                            <span class="file-type">.php (PHP)</span>
                            <span class="file-type">.html (HTML)</span>
                            <span class="file-type">.cs (C#)</span>
                            <span class="file-type">.rb (Ruby)</span>
                            <span class="file-type">.zip (压缩包)</span>
                        </div>
                    </div>

                    <input type="file" id="file" name="file" accept=".py,.js,.java,.php,.html,.cs,.rb,.zip" style="display: none;">
                </div>

                <button type="submit" class="btn btn-block">开始代码审计</button>
            </form>
        </div>

        <div class="feature-cards">
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3>全面漏洞检测</h3>
                <p>检测SQL注入、XSS、命令注入等7大类安全漏洞</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3>详细分析报告</h3>
                <p>提供漏洞位置、严重程度和修复建议的详细报告</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">🔄</div>
                <h3>多语言支持</h3>
                <p>支持Python、Java、JavaScript、PHP等多种编程语言</p>
            </div>
        </div>

        <div class="card">
            <h2 class="card-title">安全检测规则</h2>
            <p>系统内置的安全规则库，持续更新中：</p>

            {% for rule in rules %}
            <div class="rule-card {% if rule.severity == '中危' %}medium{% elif rule.severity == '低危' %}low{% endif %}">
                <h3>
                    {{ rule.name }}
                    <span class="severity-badge 
                        {% if rule.severity == '高危' %}severity-high
                        {% elif rule.severity == '中危' %}severity-medium
                        {% else %}severity-low{% endif %}">
                        {{ rule.severity }}
                    </span>
                </h3>
                <p>{{ rule.description }}</p>
                <p>支持语言: {{ rule.languages|join(', ') }}</p>
            </div>
            {% endfor %}
        </div>
    </main>

    <footer>
        <div class="container">
            <p>代码安全审计系统 &copy; {{ now.strftime('%Y') }} - 让代码更安全</p>
            <p>最后更新: {{ now.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </footer>

    <script>
        // 文件上传区域交互
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file');

        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#e94560';
            uploadArea.style.backgroundColor = 'rgba(233, 69, 96, 0.1)';
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'rgba(255, 255, 255, 0.3)';
            uploadArea.style.backgroundColor = '';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'rgba(255, 255, 255, 0.3)';
            uploadArea.style.backgroundColor = '';

            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;

                // 更新显示文件名
                const fileName = e.dataTransfer.files[0].name;
                uploadArea.querySelector('h3').textContent = `已选择文件: ${fileName}`;
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                const fileName = fileInput.files[0].name;
                uploadArea.querySelector('h3').textContent = `已选择文件: ${fileName}`;
            }
        });
    </script>
</body>
</html>""")

    # 创建 results.html
    results_path = os.path.join(templates_dir, 'results.html')
    with open(results_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>审计结果 - CodeAudit Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #e94560;
            --warning: #ff9a3c;
            --success: #0f9d58;
            --info: #4285f4;
            --text-light: #f0f0f0;
            --text-dark: #333;
            --card-bg: rgba(255, 255, 255, 0.08);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text-light);
            min-height: 100vh;
            background-attachment: fixed;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(10, 10, 20, 0.85);
            backdrop-filter: blur(10px);
            padding: 15px 0;
            border-bottom: 1px solid rgba(233, 69, 96, 0.3);
            position: sticky;
            top极 0;
            z-index: 100;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 1.8rem;
            color: var(--text-light);
            text-decoration: none;
        }

        .logo-icon {
            color: var(--accent);
            font-size: 2rem;
        }

        .hero {
            padding: 50px 0 30px;
            text-align: center;
        }

        .hero h1 {
            font-size: 2.5rem;
            margin-bottom: 15px;
            font-weight: 700;
            background: linear-gradient(45deg, var(--accent), var(--warning));
            -webkit-background-clip: text;
            background-cl极 text;
            color: transparent;
            font-family: 'Orbitron', sans-serif;
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .card-title {
            font-size: 1.6rem;
            margin-bottom: 20px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 10px 0;
        }

        .stat-high {
            color: var(--accent);
        }

        .stat-medium {
            color: var(--warning);
        }

        .stat-low {
            color: var(--info);
        }

        .file-results {
            margin-top: 30px;
        }

        .file-card {
            background: rgba(0, 0, 0, 0.15);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }

        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .vuln-item {
            background: rgba(233, 69, 96, 0.1);
            border-left: 3px solid var(--accent);
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
        }

        .vuln-item.medium {
            background: rgba(255, 154, 60, 0.1);
            border-left-color: var(--warning);
        }

        .vuln-item.low {
            background: rgba(66, 133, 244, 0.1);
            border-left-color: var(--info);
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .code-snippet {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
            padding: 15px;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 10px;
            overflow-x: auto;
        }

        .highlight {
            background: rgba(233, 69, 96, 0.3);
            padding: 2px 4px;
            border-radius: 3px;
        }

        .chart-container {
            height: 300px;
            margin: 30px 0;
        }

        .fix-link {
            color: var(--info);
            text-decoration: none;
            margin-left: 10px;
        }

        .fix-link:hover {
            text-decoration: underline;
        }

        .btn {
            display: inline-block;
            background: var(--accent);
            color: white;
            border: none;
            padding: 12px 25px;
            font-size: 1rem;
            font-weight: 500;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
            text-decoration: none;
            margin-top: 20px;
        }

        .btn:hover {
            background: #ff2e4f;
            transform: translateY(-3px);
            box-shadow: 0 7px 15px rgba(233, 69, 96, 0.3);
        }

        footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 60px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: rgba(255, 255, 255, 0.6);
        }

        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .severity-high {
            background: var(--accent);
        }

        .severity-critical {
            background: #d32f2f;
        }

        .severity-medium {
            background: var(--warning);
        }

        /* Responsive styles */
        @media (max-width: 768px) {
            .stats-container {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="navbar">
                <a href="/" class="logo">
                    <span class="logo-icon">🔍</span>
                    <span>CodeAudit Pro</span>
                </a>
            </div>
        </div>
    </header>

    <main class="container">
        <div class="hero">
            <h1>代码审计结果</h1>
            <p>分析完成，发现 {{ total_vulnerabilities }} 个潜在安全问题</p>
        </div>

        <div class="card">
            <div class="stats-container">
                <div class="stat-card">
                    <div>扫描文件</div>
                    <div class="stat-value">{{ total_files }}</div>
                    <div>个文件</div>
                </div>

                <div class="stat-card">
                    <div>存在漏洞的文件</div>
                    <div class="stat-value">{{ vulnerable_files }}</div>
                    <div>个文件</div>
                </div>

                <div class="stat-card">
                    <div>高危漏洞</div>
                    <div class="stat-value stat-high">{{ severity_count.高危 }}</div>
                    <div>需要立即修复</div>
                </div>

                <div class="stat-card">
                    <div>中危漏洞</div>
                    <div class="stat-value stat-medium">{{ severity_count.中危 }}</div>
                    <div>建议修复</div>
                </div>

                <div class="stat-card">
                    <div>低危漏洞</div>
                    <div class="stat-value stat-low">{{ severity_count.低危 }}</div>
                    <div>优化建议</div>
                </div>
            </div>

            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>

            <div class="file-results">
                <h2 class="card-title">详细结果</h2>

                {% for result in results %}
                <div class="file-card">
                    <div class="file-header">
                        <h3>{{ result.file }}</h3>
                        <div class="status-badge {% if result.vulnerable %}status-vulnerable{% else %}status-safe{% endif %}">
                            {% if result.vulnerable %}存在漏洞{% else %}安全{% endif %}
                        </div>
                    </div>

                    <p>{{ result.message }}</p>

                    {% if result.details %}
                        {% for vuln in result.details %}
                        <div class="vuln-item {% if vuln.severity == '中危' %}medium{% elif vuln.severity == '低危' %}low{% endif %}">
                            <div class="vuln-header">
                                <div>
                                    <strong>{{ vuln.rule_name }}</strong> 
                                    <span class="severity-badge 
                                        {% if vuln.severity == '高危' %}severity-high
                                        {% elif vuln.severity == '中危' %}severity-medium
                                        {% else %}severity-low{% endif %}">
                                        {{ vuln.severity }}
                                    </span>
                                </div>
                                <div>行号: {{ vuln.line }}</div>
                            </div>

                            <p>{{ vuln.description }}</p>

                            <div class="code-snippet">
                                {% for line in vuln.context %}
                                {% if loop.index0 == 1 %}
                                <div class="highlight">{{ vuln.line + loop.index0 - 1 }}: {{ line }}</div>
                                {% else %}
                                <div>{{ vuln.line + loop.index0 - 1 }}: {{ line }}</div>
                                {% endif %}
                                {% endfor %}
                            </div>

                            <p>
                                <a href="/fix/{{ vuln.rule_id }}" class="fix-link">查看修复建议 →</a>
                            </p>
                        </div>
                        {% endfor %}
                    {% endif %}
                </div>
                {% endfor %}
            </div>

            <a href="/" class="btn">重新扫描</a>
        </div>
    </main>

    <footer>
        <div class="container">
            <p>代码安全审计系统 &copy; {{ now.strftime('%Y') }} - 让代码更安全</p>
            <p>扫描完成时间: {{ now.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </footer>

    <script>
        // 漏洞严重程度图表
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['高危漏洞', '中危漏洞', '低危漏洞'],
                datasets: [{
                    data: [
                        {{ severity_count.高危 }},
                        {{ severity_count.中危 }},
                        {{ severity_count.低危 }}
                    ],
                    backgroundColor: [
                        'rgba(233, 69, 96, 0.8)',
                        'rgba(255, 154, 60, 0.8)',
                        'rgba(66, 133, 244, 0.8)'
                    ],
                    borderColor: [
                        'rgba(233, 69, 96, 1)',
                        'rgba(255, 154, 60, 1)',
                        'rgba(66, 133, 244, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f0f0f0',
                            font: {
                                size: 14
                            }
                        }
                    },
                    title: {
                        display: true,
                        text: '漏洞严重程度分布',
                        color: '#f0f0f0',
                        font: {
                            size: 18
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.chart.getDatasetMeta(0).total;
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });

        // 展开/折叠漏洞详情
        document.querySelectorAll('.vuln-item').forEach(item => {
            const codeSnippet = item.querySelector('.code-snippet');
            codeSnippet.style.display = 'none';

            item.addEventListener('click', function() {
                if (codeSnippet.style.display === 'none') {
                    codeSnippet.style.display = 'block';
                } else {
                    codeSnippet.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>""")

    # 创建 fix.html
    fix_path = os.path.join(templates_dir, 'fix.html')
    with open(fix_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>修复建议 - CodeAudit Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #e94560;
            --warning: #ff9a3c;
            --success: #0f9d58;
            --info: #4285f4;
            --text-light: #f0f0f0;
            --text-dark: #333;
            --card-bg: rgba(255, 255, 255, 0.08);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text-light);
            min-height: 100vh;
            background-attachment: fixed;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            background: rgba(10, 10, 20, 0.85);
            backdrop-filter: blur(10px);
            padding: 15px 0;
            border-bottom: 1px solid rgba(233, 69, 96, 0.3);
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 1.8rem;
            color: var(--text-light);
            text-decoration: none;
        }

        .logo-icon {
            color: var(--accent);
            font-size: 2rem;
        }

        .hero {
            padding: 50px 0 30px;
            text-align: center;
        }

        .hero h1 {
            font-size: 2.5rem;
            margin-bottom: 15px;
            font-weight: 700;
            background: linear-gradient(45deg, var(--accent), var(--warning));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            font-family: 'Orbitron', sans-serif;
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .card-title {
            font-size: 1.6rem;
            margin-bottom: 20px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .vuln-info {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .severity-display {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 1.1rem;
            font-weight: 500;
            margin-bottom: 15px;
        }

        .severity-high {
            background: var(--accent);
        }

        .severity-medium {
            background: var(--warning);
        }

        .severity-low {
            background: var(--info);
        }

        .fix-section {
            margin-bottom: 30px;
        }

        .code-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }

        @media (max-width: 768px) {
            .code-comparison {
                grid-template-columns: 1fr;
            }
        }

        .code-block {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 15px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }

        .bad-code {
            border-left: 4px solid var(--accent);
        }

        .good-code {
            border-left: 4px solid var(--success);
        }

        .code-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }

        .bad-header {
            color: var(--accent);
        }

        .good-header {
            color: var(--success);
        }

        .recommendations {
            background: rgba(15, 157, 88, 0.1);
            border-left: 4px solid var(--success);
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }

        .recommendations ul {
            padding-left: 20px;
        }

        .recommendations li {
            margin-bottom: 10px;
        }

        .btn {
            display: inline-block;
            background: var(--accent);
            color: white;
            border: none;
            padding: 12px 25px;
            font-size: 1rem;
            font-weight: 500;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
            text-decoration: none;
        }

        .btn:hover {
            background: #ff2e4f;
            transform: translateY(-3px);
            box-shadow: 0 7px 15px rgba(233, 69, 96, 0.3);
        }

        footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 60px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: rgba(255, 255, 255, 0.6);
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="navbar">
                <a href="/" class="logo">
                    <span class="logo-icon">🔍</span>
                    <span>CodeAudit Pro</span>
                </a>
            </div>
        </极>
    </header>

    <main class="container">
        <div class="hero">
            <h1>漏洞修复建议</h1>
            <p>{{ rule.name }} - {{ rule.severity }}</p>
        </div>

        <div class="card">
            <div class="vuln-info">
                <div class="severity-display 
                    {% if rule.severity == '高危' %}severity-high
                    {% elif rule.severity == '中危' %}severity-medium
                    {% else %}severity-low{% endif %}">
                    {{ rule.severity }}漏洞
                </div>

                <h2>{{ rule.name }}</h2>
                <p>{{ rule.description }}</p>
                <p>支持检测的语言: {{ rule.languages|join(', ') }}</p>
            </div>

            <div class="fix-section">
                <h3 class="card-title">问题代码示例</h3>
                <div class="code-block bad-code">
{{ rule.example.bad }}
                </div>
            </div>

            <div class="fix-section">
                <h3 class="card-title">安全修复方案</h3>
                <div class="code-block good-code">
{{ rule.example.good }}
                </div>
            </div>

            <div class="recommendations">
                <h3>安全最佳实践</h3>
                <ul>
                    {% for recommendation in rule.recommendations %}
                    <li>{{ recommendation }}</li>
                    {% endfor %}
                </ul>
            </div>

            <a href="/" class="btn">返回首页</a>
        </div>
    </main>

    <footer>
        <div class="container">
            <p>代码安全审计系统 &copy; {{ now.strftime('%Y') }} - 让代码更安全</p>
            <p>最后更新时间: {{ now.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </footer>
</body>
</html>""")

    # 创建 404.html
    not_found_path = os.path.join(templates_dir, '404.html')
    with open(not_found_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>页面未找到 - CodeAudit Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #e94560;
            --text-light: #f0f0f0;
        }

        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text-light);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 20px;
        }

        .error-code {
            font-size: 8rem;
            font-weight: 700;
            background: linear-gradient(45deg, var(--accent), #ff9a3c);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 20px;
        }

        .error-message {
            font-size: 2rem;
            margin-bottom: 30px;
        }

        .btn {
            display: inline-block;
            background: var(--accent);
            color: white;
            border: none;
            padding: 14px 30px;
            font-size: 1.1rem;
            font-weight: 500;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-align: center;
            text-decoration: none;
        }

        .btn:hover {
            background: #ff2e4f;
            transform: translateY(-3px);
            box-shadow: 0 7px 15px rgba(233, 69, 96, 0.3);
        }
    </style>
</head>
<body>
    <div class="error-code">404</div>
    <div class="error-message">页面未找到</div>
    <p>请求的页面不存在，请检查URL是否正确</p>
    <a href="/" class="btn">返回首页</a>
</body>
</html>""")


# 运行应用
if __name__ == '__main__':
    # 确保模板目录和文件存在
    ensure_template_directory()

    # 运行应用
    app.run(host='0.0.0.0', port=5000, debug=True)
