# 安全工具箱 - 综合安全工具平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green)
![License](https://img.shields.io/badge/License-MIT-orange)

安全工具箱是一个集成了多种网络安全工具的桌面应用程序，提供用户友好的界面和强大的安全功能，包括域名检测、端口扫描、漏洞扫描等工具。

## 主要功能

- **用户管理系统**
  - 安全注册与登录
  - 密码哈希加密存储
  - 记住密码功能（下次启动自动填充用户名）

- **安全工具模块**
  - 🌐 域名检测工具
  - 🔍 端口扫描工具
  - 🛡️ 漏洞扫描工具
  - 📊 日志分析工具
  - 📶 网络监控工具
  - 🔒 加密工具

- **用户体验优化**
  - 响应式界面设计
  - 密码显示/隐藏功能
  - 多窗口管理
  - 模块化设计，易于扩展

## 技术栈

- **核心语言**: Python 3.8+
- **GUI框架**: Tkinter
- **Web集成**: PyWebView
- **安全机制**: SHA-256密码哈希加密
- **数据存储**: JSON文件存储
- **网络工具**: Socket, Flask

## 安装与运行

### 前置要求
- Python 3.8 或更高版本
- pip 包管理工具

### 安装步骤

1. **克隆仓库**
   ```bash
   git clone https://github.com/yourusername/security-toolbox.git
   cd security-toolbox
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **运行应用**
   ```bash
   python run.py
   ```

## 使用说明

### 注册与登录
1. 首次使用需注册账号
2. 输入用户名、密码和有效邮箱
3. 登录后可选择"记住密码"，下次启动自动填充用户名

### 主要功能界面
登录后进入主界面：
- 点击工具图标启动相应功能
- 域名检测工具会在独立窗口中打开
- 其他工具暂为占位功能（开发中）

### 退出系统
- 点击"注销"返回登录界面
- 点击"退出系统"关闭应用

## 模块开发指南

### 添加新工具模块
1. 在项目目录中创建新模块文件（如 `PortScanner.py`）
2. 实现工具功能
3. 在 `run.py` 的 `show_main_menu` 方法中添加新模块按钮：
   ```python
   modules = [
       # ... 现有模块 ...
       {"name": "端口扫描", "command": self.run_port_scanner, "icon": "🔍"},
   ]
   ```
4. 实现对应的启动方法（如 `run_port_scanner`）

### 与Flask服务集成
对于需要Web界面的工具：
1. 创建Flask应用
2. 在 `run_domain_detection` 方法中参考现有实现：
   ```python
   def run_port_scanner(self):
       # 启动Flask服务的类似逻辑
       pass
   ```

## 项目结构

```
security-toolbox/
├── run.py                  # 主程序入口
├── users.json              # 用户数据存储
├── DomainDetection.py      # 域名检测模块
├── requirements.txt        # 依赖列表
├── README.md               # 项目文档
└── docs/                   # 文档目录
    └── design.md           # 设计文档
```

## 贡献指南

欢迎贡献代码！请遵循以下流程：
1. Fork 项目仓库
2. 创建新分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -am 'Add some feature'`)
4. 推送分支 (`git push origin feature/your-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 [MIT 许可证](LICENSE)

## 联系方式

如有任何问题或建议，请联系：
- 邮箱：security-toolbox@example.com
- 项目地址：https://github.com/yourusername/security-toolbox

---

**安全工具箱** - 为网络安全专业人士和爱好者提供的一站式安全工具平台
