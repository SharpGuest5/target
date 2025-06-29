import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import threading
import ipaddress
import re
from datetime import datetime
import time
import select
import os
import struct
import platform
import random


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("高级网络安全扫描器")
        self.root.geometry("1100x750")
        self.root.configure(bg="#f5f7ff")
        self.root.resizable(True, True)

        # 扫描状态
        self.scanning = False
        self.stop_scan = False
        self.progress_value = 0
        self.last_update = 0
        self.host_discovery_enabled = True
        self.service_version_detection = False
        self.os_detection = False
        self.current_scan_type = "TCP Connect"

        # 创建界面
        self.create_widgets()

        # 设置初始值
        self.target_entry.insert(0, "127.0.0.1")
        self.port_entry.insert(0, "1-1024")
        self.scan_type_var.set("TCP Connect")
        self.host_discovery_var.set(1)  # 默认启用主机发现
        self.service_version_var.set(0)  # 默认禁用服务版本探测
        self.os_detection_var.set(0)  # 默认禁用OS探测

    def set_styles(self):
        # 自定义样式
        style = ttk.Style()

        # 标题样式
        style.configure("Title.TLabel",
                        font=("Segoe UI", 20, "bold"),
                        foreground="#000000",
                        background="#f5f7ff")

        # 副标题样式
        style.configure("Subtitle.TLabel",
                        font=("Segoe UI", 11),
                        foreground="#000000",
                        background="#f5f7ff")

        # 标签样式
        style.configure("Label.TLabel",
                        font=("Segoe UI", 10),
                        foreground="#000000",
                        background="#ffffff")

        # 输入框样式
        style.configure("Entry.TEntry",
                        font=("Segoe UI", 10),
                        foreground="#000000",
                        padding=8,
                        bordercolor="#bdc3c7",
                        lightcolor="#ffffff",
                        darkcolor="#ffffff",
                        fieldbackground="#ffffff")

        # 按钮样式
        style.configure("Primary.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="#000000",
                        background="#3498db",
                        padding=8,
                        borderwidth=0)

        style.map("Primary.TButton",
                  background=[("active", "#2980b9")])

        style.configure("Success.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="#000000",
                        background="#2ecc71",
                        padding=8,
                        borderwidth=0)

        style.map("Success.TButton",
                  background=[("active", "#27ae60")])

        style.configure("Danger.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="#000000",
                        background="#e74c3c",
                        padding=8,
                        borderwidth=0)

        style.map("Danger.TButton",
                  background=[("active", "#c0392b")])

        # 框架样式
        style.configure("Card.TFrame",
                        background="#ffffff",
                        borderwidth=1,
                        relief="solid",
                        bordercolor="#dfe6e9")

        # 进度条样式
        style.configure("Horizontal.TProgressbar",
                        thickness=6,
                        troughcolor="#ecf0f1",
                        background="#2ecc71",
                        lightcolor="#2ecc71",
                        darkcolor="#27ae60",
                        bordercolor="#ecf0f1")

    def create_widgets(self):
        # 创建主容器
        main_frame = tk.Frame(self.root, bg="#f5f7ff")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # 标题区域
        header_frame = tk.Frame(main_frame, bg="#f5f7ff")
        header_frame.pack(fill=tk.X, pady=(0, 15))

        title_label = ttk.Label(header_frame, text="高级端口扫描器", style="Title.TLabel")
        title_label.pack(side=tk.LEFT, anchor="nw")

        subtitle_label = ttk.Label(header_frame,
                                   text="支持多种扫描技术、主机发现、服务版本探测和操作系统识别",
                                   style="Subtitle.TLabel")
        subtitle_label.pack(side=tk.LEFT, anchor="nw", padx=10, pady=(10, 0))

        # 主内容区域
        content_frame = tk.Frame(main_frame, bg="#f5f7ff")
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 左侧输入面板
        input_frame = tk.Frame(content_frame, bg="#f5f7ff", width=350)
        input_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        input_frame.pack_propagate(False)  # 防止内容改变宽度

        # 使用Canvas和Frame创建可滚动区域
        canvas = tk.Canvas(input_frame, bg="#f5f7ff", highlightthickness=0)
        scrollbar = ttk.Scrollbar(input_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # 目标设置卡片
        target_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
        target_card.pack(fill=tk.X, pady=(0, 15), padx=5, ipadx=10, ipady=10)

        card_title = ttk.Label(target_card, text="目标设置", style="Label.TLabel",
                               font=("Segoe UI", 11, "bold"))
        card_title.pack(anchor=tk.W, pady=(0, 10))

        # 目标输入
        target_form = tk.Frame(target_card, bg="#ffffff")
        target_form.pack(fill=tk.X, pady=5)

        target_label = ttk.Label(target_form, text="目标地址:", style="Label.TLabel")
        target_label.pack(anchor=tk.W, padx=5)

        self.target_entry = ttk.Entry(target_form, style="Entry.TEntry")
        self.target_entry.pack(fill=tk.X, padx=5, pady=5, ipady=5)
        self.target_entry.insert(0, "127.0.0.1")

        tip_label = ttk.Label(target_form, text="支持IP、域名、CIDR网段(192.168.1.0/24)或逗号分隔",
                              style="Label.TLabel", font=("Segoe UI", 8))
        tip_label.pack(anchor=tk.W, padx=5, pady=(0, 5))

        # 主机发现设置
        discovery_frame = tk.Frame(target_card, bg="#ffffff")
        discovery_frame.pack(fill=tk.X, pady=5)

        self.host_discovery_var = tk.IntVar(value=1)
        host_discovery_check = ttk.Checkbutton(discovery_frame,
                                               text="启用主机发现 (Ping扫描)",
                                               variable=self.host_discovery_var,
                                               style="Label.TLabel")
        host_discovery_check.pack(anchor=tk.W, padx=5, pady=5)

        # 端口管理卡片
        port_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
        port_card.pack(fill=tk.X, pady=(0, 15), padx=5, ipadx=10, ipady=10)

        card_title = ttk.Label(port_card, text="端口设置", style="Label.TLabel",
                               font=("Segoe UI", 11, "bold"))
        card_title.pack(anchor=tk.W, pady=(0, 10))

        # 端口输入
        port_form = tk.Frame(port_card, bg="#ffffff")
        port_form.pack(fill=tk.X, pady=5)

        port_label = ttk.Label(port_form, text="扫描端口:", style="Label.TLabel")
        port_label.pack(anchor=tk.W, padx=5)

        self.port_entry = ttk.Entry(port_form, style="Entry.TEntry")
        self.port_entry.pack(fill=tk.X, padx=5, pady=5, ipady=5)
        self.port_entry.insert(0, "1-1024")

        tip_label = ttk.Label(port_form, text="支持单个端口(80)、范围(1-100)、逗号分隔(80,443,8080)",
                              style="Label.TLabel", font=("Segoe UI", 8))
        tip_label.pack(anchor=tk.W, padx=5, pady=(0, 5))

        # 预设端口按钮
        preset_btn_frame = tk.Frame(port_card, bg="#ffffff")
        preset_btn_frame.pack(fill=tk.X, pady=5)

        top_btn = ttk.Button(preset_btn_frame, text="常用端口",
                             style="Primary.TButton",
                             command=lambda: self.set_preset_ports("common"))
        top_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # 修正了这里的拼写错误：ttt -> ttk
        web_btn = ttk.Button(preset_btn_frame, text="Web服务",
                             style="Primary.TButton",
                             command=lambda: self.set_preset_ports("web"))
        web_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        full_btn = ttk.Button(preset_btn_frame, text="全端口",
                              style="Primary.TButton",
                              command=lambda: self.set_preset_ports("full"))
        full_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 扫描设置卡片
        settings_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
        settings_card.pack(fill=tk.X, padx=5, pady=(0, 15), ipadx=10, ipady=10)

        card_title = ttk.Label(settings_card, text="扫描设置", style="Label.TLabel",
                               font=("Segoe UI", 11, "bold"))
        card_title.pack(anchor=tk.W, pady=(0, 10))

        # 扫描类型选择
        scan_type_frame = tk.Frame(settings_card, bg="#ffffff")
        scan_type_frame.pack(fill=tk.X, pady=5)

        scan_type_label = ttk.Label(scan_type_frame, text="扫描类型:", style="Label.TLabel")
        scan_type_label.pack(anchor=tk.W, padx=5)

        # 扫描类型下拉菜单
        self.scan_type_var = tk.StringVar()
        scan_types = ["TCP Connect", "TCP SYN", "TCP FIN", "UDP", "快速扫描", "全面扫描"]
        scan_type_combo = ttk.Combobox(scan_type_frame,
                                       textvariable=self.scan_type_var,
                                       values=scan_types,
                                       state="readonly",
                                       width=15)
        scan_type_combo.pack(anchor=tk.W, padx=5, pady=5)
        self.scan_type_var.set("TCP Connect")  # 设置默认值

        # 高级选项
        advanced_frame = tk.Frame(settings_card, bg="#ffffff")
        advanced_frame.pack(fill=tk.X, pady=5)

        self.service_version_var = tk.IntVar(value=0)
        service_check = ttk.Checkbutton(advanced_frame,
                                        text="服务版本探测",
                                        variable=self.service_version_var,
                                        style="Label.TLabel")
        service_check.pack(anchor=tk.W, padx=5, pady=5)

        self.os_detection_var = tk.IntVar(value=0)
        os_check = ttk.Checkbutton(advanced_frame,
                                   text="操作系统探测",
                                   variable=self.os_detection_var,
                                   style="Label.TLabel")
        os_check.pack(anchor=tk.W, padx=5, pady=5)

        # TCP连接超时设置
        timeout_frame = tk.Frame(settings_card, bg="#ffffff")
        timeout_frame.pack(fill=tk.X, pady=5)

        timeout_label = ttk.Label(timeout_frame, text="连接超时(秒):", style="Label.TLabel")
        timeout_label.pack(anchor=tk.W, padx=5)

        self.timeout_var = tk.DoubleVar(value=0.5)
        timeout_spin = ttk.Spinbox(timeout_frame, from_=0.1, to=10, increment=0.1,
                                   textvariable=self.timeout_var, width=8)
        timeout_spin.pack(anchor=tk.W, padx=5, pady=5)

        # 线程设置
        thread_frame = tk.Frame(settings_card, bg="#ffffff")
        thread_frame.pack(fill=tk.X, pady=5)

        thread_label = ttk.Label(thread_frame, text="并发线程数:", style="Label.TLabel")
        thread_label.pack(anchor=tk.W, padx=5)

        self.thread_var = tk.IntVar(value=100)
        thread_spin = ttk.Spinbox(thread_frame, from_=1, to=500, increment=10,
                                  textvariable=self.thread_var, width=8)
        thread_spin.pack(anchor=tk.W, padx=5, pady=5)

        # 扫描按钮
        scan_frame = tk.Frame(settings_card, bg="#ffffff")
        scan_frame.pack(fill=tk.X, pady=10)

        btn_frame = tk.Frame(scan_frame, bg="#ffffff")
        btn_frame.pack(fill=tk.X)

        self.scan_btn = ttk.Button(btn_frame, text="开始扫描",
                                   style="Success.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.export_btn = ttk.Button(btn_frame, text="导出结果",
                                     style="Primary.TButton",
                                     command=self.export_results)
        self.export_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 右侧结果面板
        result_frame = tk.Frame(content_frame, bg="#f5f7ff")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 结果卡片
        result_card = ttk.Frame(result_frame, style="Card.TFrame")
        result_card.pack(fill=tk.BOTH, expand=True, padx=5, ipadx=10, ipady=10)

        # 结果标题
        result_header = tk.Frame(result_card, bg="#ffffff")
        result_header.pack(fill=tk.X, pady=(0, 10))

        result_title = ttk.Label(result_header, text="扫描结果",
                                 style="Label.TLabel",
                                 font=("Segoe UI", 11, "bold"))
        result_title.pack(side=tk.LEFT, anchor="w")

        # 结果统计
        self.result_stats = ttk.Label(result_header,
                                      text="就绪",
                                      style="Label.TLabel",
                                      foreground="#000000")
        self.result_stats.pack(side=tk.RIGHT, anchor="e")

        # 进度条
        self.progress = ttk.Progressbar(result_card,
                                        style="Horizontal.TProgressbar",
                                        mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, 10))

        # 结果文本框
        result_text_frame = tk.Frame(result_card, bg="#ffffff")
        result_text_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = scrolledtext.ScrolledText(result_text_frame,
                                                     font=("Consolas", 10),
                                                     wrap=tk.WORD,
                                                     padx=10, pady=10,
                                                     bg="#f8f9fa",
                                                     fg="#000000",
                                                     relief="flat",
                                                     borderwidth=0)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.result_text.config(state=tk.DISABLED)

        # 配置文本标签
        self.result_text.tag_config("open", foreground="#27ae60")
        self.result_text.tag_config("closed", foreground="#7f8c8d")
        self.result_text.tag_config("summary", foreground="#2c3e50", font=("Segoe UI", 10, "bold"))
        self.result_text.tag_config("timeout", foreground="#f39c12")
        self.result_text.tag_config("error", foreground="#e74c3c")
        self.result_text.tag_config("host", foreground="#3498db", font=("Segoe UI", 10, "bold"))
        self.result_text.tag_config("service", foreground="#9b59b6")
        self.result_text.tag_config("os", foreground="#e67e22")

        # 技术说明区域
        info_frame = tk.Frame(result_card, bg="#ffffff")
        info_frame.pack(fill=tk.X, pady=(10, 0))

        info_label = ttk.Label(info_frame,
                               text="技术原理: TCP Connect(三次握手), SYN(半开扫描), FIN(隐蔽扫描), UDP(UDP探测)",
                               style="Label.TLabel",
                               foreground="#3498db")
        info_label.pack(anchor=tk.W)

        # 状态栏
        status_bar = tk.Frame(self.root, bg="#2c3e50", height=24)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="就绪 | 高级扫描器已初始化")
        status_label = tk.Label(status_bar,
                                textvariable=self.status_var,
                                bg="#2c3e50",
                                fg="#ffffff",
                                font=("Segoe UI", 9),
                                anchor="w",
                                padx=10)
        status_label.pack(fill=tk.X)

    def set_preset_ports(self, preset_type):
        """设置预设端口范围"""
        if preset_type == "common":
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,8080,8443")
            self.status_var.set("已设置常用端口")
        elif preset_type == "web":
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "80,443,8080,8443,8000,8008,8081,8888,9080,9443")
            self.status_var.set("已设置Web服务端口")
        elif preset_type == "full":
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, "1-65535")
            self.status_var.set("已设置全端口扫描")

    def parse_targets(self, target_str):
        """解析目标字符串，支持IP、域名、CIDR网段和逗号分隔"""
        targets = []

        # 处理逗号分隔的目标
        parts = [part.strip() for part in target_str.split(',') if part.strip()]

        for part in parts:
            try:
                # 检查是否是CIDR网段
                if '/' in part:
                    network = ipaddress.ip_network(part, strict=False)
                    for ip in network.hosts():
                        targets.append(str(ip))
                else:
                    # 检查是否是IP地址
                    try:
                        ipaddress.ip_address(part)
                        targets.append(part)
                    except ValueError:
                        # 尝试解析为域名
                        try:
                            ips = socket.gethostbyname_ex(part)[2]
                            targets.extend(ips)
                        except socket.gaierror:
                            self.result_text.insert(tk.END, f"[!] 无法解析目标: {part}\n", "error")
            except Exception as e:
                self.result_text.insert(tk.END, f"[!] 目标解析错误: {part} - {str(e)}\n", "error")

        # 去重
        return list(set(targets))

    def parse_ports(self, port_str):
        """解析端口字符串，支持单个端口、范围和逗号分隔"""
        ports = []

        # 处理逗号分隔的端口
        parts = [part.strip() for part in port_str.split(',') if part.strip()]

        for part in parts:
            if '-' in part:
                # 处理端口范围
                try:
                    start, end = part.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())

                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        raise ValueError("无效的端口范围")

                    ports.extend(range(start_port, end_port + 1))
                except Exception as e:
                    self.result_text.insert(tk.END, f"[!] 无效的端口范围: {part} - {str(e)}\n", "error")
            else:
                # 处理单个端口
                try:
                    port = int(part.strip())
                    if port < 1 or port > 65535:
                        raise ValueError("端口号超出范围")
                    ports.append(port)
                except Exception as e:
                    self.result_text.insert(tk.END, f"[!] 无效的端口: {part} - {str(e)}\n", "error")

        # 去重
        return list(set(ports))

    def host_discovery(self, target):
        """主机发现功能 (Ping扫描)"""
        try:
            # 使用系统Ping命令
            param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            command = f"ping {param} {target}"
            response = os.system(command)

            return response == 0
        except:
            # 尝试TCP Ping
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, 80))
                s.close()
                return True
            except:
                return False

    def detect_service_version(self, target, port):
        """服务版本探测"""
        try:
            # 尝试连接并获取banner
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))

            # 发送一个简单的探测请求
            if port == 80 or port == 8080 or port == 443:
                s.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                s.send(b"USER anonymous\r\n")
            elif port == 22:
                s.send(b"SSH-2.0-Client\r\n")
            elif port == 25:
                s.send(b"EHLO example.com\r\n")
            elif port == 3306:
                s.send(b"\x0a")  # MySQL探测

            # 接收响应
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()

            # 提取服务信息
            service = socket.getservbyport(port, 'tcp') if port in range(1, 1024) else "unknown"

            # 尝试识别服务类型
            if "HTTP" in banner or "html" in banner.lower():
                service = "HTTP"
            elif "SSH" in banner:
                service = "SSH"
            elif "FTP" in banner:
                service = "FTP"
            elif "SMTP" in banner:
                service = "SMTP"

            return f"{service} | {banner[:50]}{'...' if len(banner) > 50 else ''}"
        except:
            try:
                # 回退到端口服务名称
                return socket.getservbyport(port)
            except:
                return "未知服务"

    def detect_os(self, target):
        """操作系统探测 (简化版)"""
        try:
            # 使用TTL值猜测操作系统
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, 80))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()

            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "其他/未知"
        except:
            # 使用默认方法
            try:
                # 尝试连接其他端口
                ports = [22, 25, 53, 443]
                for port in ports:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((target, port))
                        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                        s.close()

                        if ttl <= 64:
                            return "Linux/Unix"
                        elif ttl <= 128:
                            return "Windows"
                    except:
                        continue
            except:
                pass

            return "未知操作系统"

    def start_scan(self):
        """开始端口扫描"""
        if self.scanning:
            self.stop_scan = True
            self.scan_btn.config(text="开始扫描")
            self.status_var.set("扫描已停止")
            self.scanning = False
            return

        # 获取目标地址
        target_str = self.target_entry.get().strip()
        if not target_str:
            messagebox.showerror("错误", "请输入目标地址")
            return

        # 解析目标
        targets = self.parse_targets(target_str)
        if not targets:
            messagebox.showerror("错误", "未解析到有效的目标地址")
            return

        # 获取端口
        port_str = self.port_entry.get().strip()
        if not port_str:
            messagebox.showerror("错误", "请输入扫描端口")
            return

        ports = self.parse_ports(port_str)
        if not ports:
            messagebox.showerror("错误", "未解析到有效的端口")
            return

        # 清空结果
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)

        # 重置进度条
        self.progress["value"] = 0
        self.progress_value = 0

        # 更新状态
        self.scanning = True
        self.stop_scan = False
        self.scan_btn.config(text="停止扫描")
        scan_type = self.scan_type_var.get()
        self.current_scan_type = scan_type
        self.status_var.set(f"正在扫描 {len(targets)} 个目标 ({scan_type})...")
        self.result_stats.config(text=f"扫描中... 0%")

        # 获取设置
        timeout = self.timeout_var.get()
        max_threads = self.thread_var.get()
        host_discovery = self.host_discovery_var.get() == 1
        service_version = self.service_version_var.get() == 1
        os_detection = self.os_detection_var.get() == 1

        # 创建线程进行扫描
        scan_thread = threading.Thread(
            target=self.scan_ports,
            args=(targets, ports, timeout, max_threads, scan_type, host_discovery, service_version, os_detection),
            daemon=True
        )
        scan_thread.start()

    def scan_ports(self, targets, ports, timeout, max_threads, scan_type, host_discovery, service_version,
                   os_detection):
        """端口扫描主函数，支持多种扫描类型和多个目标"""
        open_ports = []
        start_time = datetime.now()
        total_targets = len(targets)
        total_ports = len(ports)
        total_tasks = total_targets * total_ports
        scanned_tasks = 0
        active_hosts = []

        # 工作线程函数
        def worker():
            nonlocal scanned_tasks
            while task_queue and not self.stop_scan:
                target, port = task_queue.pop(0)
                status = ""

                # 如果启用了主机发现且主机不在活动主机列表中，跳过扫描
                if host_discovery and target not in active_hosts:
                    # 检查主机是否存活
                    if self.host_discovery(target):
                        active_hosts.append(target)
                        self.root.after(0, self.update_result, target, f"主机发现: {target} 存活", "host")
                    else:
                        self.root.after(0, self.update_result, target, f"主机发现: {target} 不存活", "host")
                        # 跳过该主机的所有端口
                        for _ in range(total_ports):
                            if task_queue and task_queue[0][0] == target:
                                task_queue.pop(0)
                        scanned_tasks += total_ports
                        continue

                try:
                    if scan_type == "TCP Connect":
                        status = self.tcp_connect_scan(target, port, timeout)
                    elif scan_type == "TCP SYN":
                        status = self.tcp_syn_scan(target, port, timeout)
                    elif scan_type == "TCP FIN":
                        status = self.tcp_fin_scan(target, port, timeout)
                    elif scan_type == "UDP":
                        status = self.udp_scan(target, port, timeout)
                    elif scan_type == "快速扫描":
                        status = self.tcp_syn_scan(target, port, 0.3)
                    elif scan_type == "全面扫描":
                        # 全面扫描使用多种技术
                        if port < 1024:  # 常用端口使用SYN扫描
                            status = self.tcp_syn_scan(target, port, 0.5)
                        else:  # 其他端口使用Connect扫描
                            status = self.tcp_connect_scan(target, port, 1.0)
                except Exception as e:
                    status = f"错误: {str(e)}"

                if "开放" in status:
                    open_ports.append((target, port))
                    # 服务版本探测
                    if service_version and "开放" in status:
                        service_info = self.detect_service_version(target, port)
                        status = f"{status} | 服务: {service_info}"

                # 更新UI
                self.root.after(0, self.update_result, target, port, status)

                # 更新计数
                scanned_tasks += 1

                # 限制UI更新频率
                current_time = time.time()
                if current_time - self.last_update > 0.1:  # 每0.1秒更新一次
                    progress = (scanned_tasks / total_tasks) * 100
                    self.root.after(0, self.update_progress, progress, scanned_tasks, total_tasks, len(open_ports))
                    self.last_update = current_time

        # 操作系统探测
        if os_detection:
            for target in targets:
                if self.stop_scan:
                    break
                os_info = self.detect_os(target)
                self.root.after(0, self.update_result, target, f"操作系统探测: {os_info}", "os")

        # 创建任务队列
        task_queue = []
        for target in targets:
            for port in ports:
                task_queue.append((target, port))

        # 创建工作线程
        threads = []
        for _ in range(min(max_threads, len(task_queue))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # 等待所有线程完成
        for t in threads:
            t.join()

        # 确保进度完成
        self.root.after(0, self.update_progress, 100, total_tasks, total_tasks, len(open_ports))

        # 扫描完成
        self.scanning = False
        self.root.after(0, self.scan_completed, open_ports, start_time, scan_type)

    def tcp_connect_scan(self, target, port, timeout):
        """TCP连接扫描（完整三次握手）"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    return "开放"
                else:
                    return "关闭"
        except socket.timeout:
            return "超时"
        except socket.error as e:
            return f"错误: {str(e)}"

    def tcp_syn_scan(self, target, port, timeout):
        """TCP SYN扫描（半开扫描）"""
        try:
            # 创建原始套接字（需要管理员/root权限）
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(timeout)

            # 构造SYN包
            s.connect((target, port))
            s.send(b'')  # 发送空数据触发SYN包

            # 等待响应
            ready = select.select([s], [], [], timeout)
            if ready[0]:
                response = s.recv(1024)
                # 检查是否是SYN-ACK响应
                if response and response[0] == 0x12:  # SYN-ACK标志
                    # 发送RST关闭连接
                    rst_packet = bytes([0x04, 0x00])  # RST标志
                    s.send(rst_packet)
                    return "开放"
                else:
                    return "关闭"
            else:
                return "超时"
        except socket.error as e:
            if e.errno == 1:  # 权限错误
                # 回退到TCP连接扫描
                self.root.after(0, lambda: messagebox.showwarning(
                    "权限警告",
                    "SYN扫描需要管理员权限，已回退到TCP连接扫描"
                ))
                return self.tcp_connect_scan(target, port, timeout)
            return f"错误: {str(e)}"
        finally:
            try:
                s.close()
            except:
                pass

    def tcp_fin_scan(self, target, port, timeout):
        """TCP FIN扫描（发送FIN包）"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)

                # 尝试设置FIN标志
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                # 发送FIN包
                try:
                    s.connect((target, port))
                    s.shutdown(socket.SHUT_WR)  # 发送FIN包

                    # 等待响应
                    response = s.recv(1024)
                    if response:
                        # 收到RST表示端口关闭
                        return "关闭"
                    else:
                        # 没有响应可能是开放端口
                        return "开放"
                except socket.timeout:
                    # 没有响应可能是开放端口
                    return "开放"
                except ConnectionResetError:
                    # 收到RST表示端口关闭
                    return "关闭"
        except socket.error as e:
            return f"错误: {str(e)}"

    def udp_scan(self, target, port, timeout):
        """UDP端口扫描"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)

                # 发送空UDP数据包
                s.sendto(b'', (target, port))

                try:
                    # 尝试接收响应
                    data, addr = s.recvfrom(1024)
                    return "开放"
                except socket.timeout:
                    # 没有响应 - 端口可能开放或被过滤
                    return "开放|过滤"
        except socket.error as e:
            return f"错误: {str(e)}"

    def update_progress(self, progress, scanned, total, open_count):
        """更新进度条和统计信息"""
        self.progress["value"] = progress
        self.result_stats.config(text=f"扫描进度: {scanned}/{total} | 开放端口: {open_count}")

    def update_result(self, target, port, status):
        """更新结果文本框"""
        self.result_text.config(state=tk.NORMAL)

        # 如果是主机发现或OS探测结果
        if isinstance(port, str):
            self.result_text.insert(tk.END, f"[*] {target}: {port}\n", "host" if "主机" in port else "os")
            self.result_text.see(tk.END)
            self.result_text.config(state=tk.DISABLED)
            return

        # 获取端口服务名称
        try:
            service = socket.getservbyport(port)
        except:
            service = "未知服务"

        # 根据状态添加不同颜色的结果
        if "开放" in status:
            result_line = f"[✓] {target}:{port:<5} 开放 | 服务: {service} ({status})\n"
            self.result_text.insert(tk.END, result_line, "open")
        elif "关闭" in status:
            result_line = f"[✗] {target}:{port:<5} 关闭\n"
            self.result_text.insert(tk.END, result_line, "closed")
        elif "超时" in status or "过滤" in status:
            result_line = f"[⌛] {target}:{port:<5} {status}\n"
            self.result_text.insert(tk.END, result_line, "timeout")
        else:
            result_line = f"[⚠] {target}:{port:<5} {status}\n"
            self.result_text.insert(tk.END, result_line, "error")

        # 自动滚动到底部
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def scan_completed(self, open_ports, start_time, scan_type):
        """扫描完成处理"""
        self.scan_btn.config(text="开始扫描")

        duration = datetime.now() - start_time
        self.status_var.set(f"扫描完成! 发现 {len(open_ports)} 个开放端口 | 耗时: {duration.total_seconds():.2f}秒")

        # 添加总结
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, "\n" + "=" * 80 + "\n", "summary")
        self.result_text.insert(tk.END, "扫描总结:\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描目标: {self.target_entry.get()}\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描端口: {self.port_entry.get()}\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描类型: {scan_type}\n", "summary")
        self.result_text.insert(tk.END, f"- 开放端口数: {len(open_ports)}\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描耗时: {duration.total_seconds():.2f}秒\n", "summary")
        self.result_text.insert(tk.END, "=" * 80 + "\n", "summary")
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

        # 更新结果统计
        self.result_stats.config(text=f"扫描完成 | 开放端口: {len(open_ports)}")

    def export_results(self):
        """导出扫描结果到文件"""
        if not self.result_text.get("1.0", tk.END).strip():
            messagebox.showwarning("警告", "没有结果可导出")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存扫描结果"
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("高级网络安全扫描结果报告\n")
                f.write("=" * 80 + "\n")
                f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目标: {self.target_entry.get()}\n")
                f.write(f"扫描端口: {self.port_entry.get()}\n")
                f.write(f"扫描类型: {self.current_scan_type}\n")
                f.write("\n扫描结果:\n")
                f.write("=" * 80 + "\n")
                f.write(self.result_text.get("1.0", tk.END))

            self.status_var.set(f"结果已导出到: {file_path}")
            messagebox.showinfo("成功", f"扫描结果已保存到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    # 设置窗口图标
    try:
        root.iconbitmap("scanner_icon.ico")
    except:
        pass

    app = PortScannerApp(root)
    root.mainloop()