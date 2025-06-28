import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import ipaddress
import re
from datetime import datetime
import time


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("网络安全检测系统 - 端口扫描模块")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f5f7ff")
        self.root.resizable(True, True)

        # 设置应用样式
        self.set_styles()

        # 创建界面
        self.create_widgets()

        # 扫描状态
        self.scanning = False
        self.stop_scan = False
        self.progress_value = 0
        self.last_update = 0

        # 设置初始值
        self.target_entry.insert(0, "127.0.0.1")
        self.port_entry.insert(0, "80")

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

        title_label = ttk.Label(header_frame, text="基于TCP三次握手的端口扫描系统", style="Title.TLabel")
        title_label.pack(side=tk.LEFT, anchor="nw")

        subtitle_label = ttk.Label(header_frame,
                                   text="通过TCP三次握手检测目标系统的开放端口",
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

        # 端口管理卡片
        port_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
        port_card.pack(fill=tk.X, pady=(0, 15), padx=5, ipadx=10, ipady=10)

        card_title = ttk.Label(port_card, text="端口管理", style="Label.TLabel",
                               font=("Segoe UI", 11, "bold"))
        card_title.pack(anchor=tk.W, pady=(0, 10))

        # 端口输入
        port_form = tk.Frame(port_card, bg="#ffffff")
        port_form.pack(fill=tk.X, pady=5)

        port_label = ttk.Label(port_form, text="添加端口:", style="Label.TLabel")
        port_label.pack(anchor=tk.W, padx=5)

        self.port_entry = ttk.Entry(port_form, style="Entry.TEntry")
        self.port_entry.pack(fill=tk.X, padx=5, pady=5, ipady=5)

        # 按钮组
        btn_frame = tk.Frame(port_form, bg="#ffffff")
        btn_frame.pack(fill=tk.X, pady=10)

        add_port_btn = ttk.Button(btn_frame, text="添加单个端口",
                                  style="Primary.TButton",
                                  command=self.add_single_port)
        add_port_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        add_range_btn = ttk.Button(btn_frame, text="添加范围",
                                   style="Primary.TButton",
                                   command=self.add_port_range)
        add_range_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 常用端口按钮
        common_btn_frame = tk.Frame(port_card, bg="#ffffff")
        common_btn_frame.pack(fill=tk.X, pady=5)

        common_btn = ttk.Button(common_btn_frame, text="添加常用端口",
                                style="Success.TButton",
                                command=self.add_common_ports)
        common_btn.pack(fill=tk.X, pady=(0, 10))

        # 端口列表
        list_frame = tk.Frame(port_card, bg="#ffffff")
        list_frame.pack(fill=tk.X, pady=5)

        list_label = ttk.Label(list_frame, text="扫描端口列表:", style="Label.TLabel")
        list_label.pack(anchor=tk.W, pady=(0, 5))

        # 端口列表框
        port_list_frame = tk.Frame(list_frame, bg="#ffffff")
        port_list_frame.pack(fill=tk.X)

        # 创建滚动条
        scrollbar = ttk.Scrollbar(port_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.port_listbox = tk.Listbox(port_list_frame,
                                       height=8,
                                       font=("Segoe UI", 9),
                                       foreground="#000000",
                                       selectbackground="#3498db",
                                       selectforeground="#ffffff",
                                       activestyle="none",
                                       highlightthickness=1,
                                       highlightcolor="#3498db",
                                       highlightbackground="#bdc3c7",
                                       yscrollcommand=scrollbar.set)
        self.port_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)

        scrollbar.config(command=self.port_listbox.yview)

        # 添加默认端口
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443]
        for port in common_ports:
            self.port_listbox.insert(tk.END, port)

        # 列表按钮
        list_btn_frame = tk.Frame(list_frame, bg="#ffffff")
        list_btn_frame.pack(fill=tk.X, pady=5)

        remove_btn = ttk.Button(list_btn_frame, text="删除选中",
                                style="Danger.TButton",
                                command=self.remove_selected_ports)
        remove_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        clear_btn = ttk.Button(list_btn_frame, text="清空列表",
                               style="Danger.TButton",
                               command=self.clear_port_list)
        clear_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 扫描设置卡片
        settings_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
        settings_card.pack(fill=tk.X, padx=5, pady=(0, 15), ipadx=10, ipady=10)

        card_title = ttk.Label(settings_card, text="扫描设置", style="Label.TLabel",
                               font=("Segoe UI", 11, "bold"))
        card_title.pack(anchor=tk.W, pady=(0, 10))

        # TCP连接超时设置
        timeout_frame = tk.Frame(settings_card, bg="#ffffff")
        timeout_frame.pack(fill=tk.X, pady=5)

        timeout_label = ttk.Label(timeout_frame, text="TCP连接超时(秒):", style="Label.TLabel")
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

        self.scan_btn = ttk.Button(scan_frame, text="开始扫描",
                                   style="Success.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(fill=tk.X)

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
        self.result_text.tag_config("open", foreground="#000000")
        self.result_text.tag_config("closed", foreground="#000000")
        self.result_text.tag_config("summary", foreground="#000000", font=("Segoe UI", 10, "bold"))

        # 技术说明区域
        info_frame = tk.Frame(result_card, bg="#ffffff")
        info_frame.pack(fill=tk.X, pady=(10, 0))

        info_label = ttk.Label(info_frame,
                               text="技术原理: 基于TCP三次握手进行端口扫描",
                               style="Label.TLabel",
                               foreground="#3498db")
        info_label.pack(anchor=tk.W)

        # 状态栏
        status_bar = tk.Frame(self.root, bg="#2c3e50", height=24)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="就绪 | 端口扫描模块已初始化")
        status_label = tk.Label(status_bar,
                                textvariable=self.status_var,
                                bg="#2c3e50",
                                fg="#ffffff",
                                font=("Segoe UI", 9),
                                anchor="w",
                                padx=10)
        status_label.pack(fill=tk.X)

    def add_single_port(self):
        """添加单个端口到列表"""
        port_str = self.port_entry.get().strip()

        if not port_str:
            messagebox.showerror("错误", "请输入端口号")
            return

        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("端口号超出范围")

            if port not in self.get_port_list():
                self.port_listbox.insert(tk.END, port)
                self.port_entry.delete(0, tk.END)
                self.status_var.set(f"已添加端口: {port}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口号 (1-65535)")

    def add_port_range(self):
        """添加端口范围到列表"""
        port_str = self.port_entry.get().strip()

        if not port_str:
            messagebox.showerror("错误", "请输入端口范围")
            return

        # 检查格式是否为 "开始-结束"
        if '-' not in port_str:
            messagebox.showerror("错误", "请输入有效的端口范围 (如: 80-100)")
            return

        try:
            start, end = port_str.split('-')
            start_port = int(start.strip())
            end_port = int(end.strip())

            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("端口范围无效")

            # 添加范围到列表
            if f"{start_port}-{end_port}" not in self.port_listbox.get(0, tk.END):
                self.port_listbox.insert(tk.END, f"{start_port}-{end_port}")
                self.port_entry.delete(0, tk.END)
                self.status_var.set(f"已添加端口范围: {start_port}-{end_port}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口范围 (如: 80-100)")

    def add_common_ports(self):
        """添加常用端口到列表"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443]
        existing_ports = self.get_port_list()

        added = False
        for port in common_ports:
            if port not in existing_ports:
                self.port_listbox.insert(tk.END, port)
                added = True

        if added:
            self.status_var.set("已添加常用端口")
        else:
            messagebox.showinfo("信息", "所有常用端口已在列表中")

    def remove_selected_ports(self):
        """删除选中的端口"""
        selected = self.port_listbox.curselection()
        if not selected:
            messagebox.showinfo("信息", "请选择要删除的端口")
            return

        # 从后往前删除，避免索引变化
        for i in selected[::-1]:
            port = self.port_listbox.get(i)
            self.port_listbox.delete(i)

        self.status_var.set(f"已删除 {len(selected)} 个端口")

    def clear_port_list(self):
        """清空端口列表"""
        if messagebox.askyesno("确认", "确定要清空所有端口吗？"):
            count = self.port_listbox.size()
            self.port_listbox.delete(0, tk.END)
            self.status_var.set(f"已清空 {count} 个端口")

    def get_port_list(self):
        """获取要扫描的所有端口列表"""
        ports = []
        for item in self.port_listbox.get(0, tk.END):
            if '-' in str(item):
                # 处理端口范围
                try:
                    start, end = map(int, item.split('-'))
                    ports.extend(range(start, end + 1))
                except:
                    continue
            else:
                try:
                    ports.append(int(item))
                except:
                    continue
        return list(set(ports))  # 去重

    def start_scan(self):
        """开始端口扫描"""
        if self.scanning:
            self.stop_scan = True
            self.scan_btn.config(text="开始扫描")
            self.status_var.set("扫描已停止")
            self.scanning = False
            return

        # 获取目标地址
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("错误", "请输入目标地址")
            return

        # 验证目标地址
        try:
            # 尝试解析域名
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                target = socket.gethostbyname(target)

            # 验证IP地址
            ipaddress.ip_address(target)
        except (socket.gaierror, ValueError):
            messagebox.showerror("错误", "无效的目标地址或域名")
            return

        # 获取端口列表
        ports = self.get_port_list()
        if not ports:
            messagebox.showerror("错误", "请添加要扫描的端口")
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
        self.status_var.set(f"正在扫描 {target}...")
        self.result_stats.config(text=f"扫描中... 0%")

        # 获取设置
        timeout = self.timeout_var.get()
        max_threads = self.thread_var.get()

        # 创建线程进行扫描
        scan_thread = threading.Thread(
            target=self.scan_ports,
            args=(target, ports, timeout, max_threads),
            daemon=True
        )
        scan_thread.start()

    def scan_ports(self, target, ports, timeout, max_threads):
        """
        基于TCP三次握手的端口扫描函数
        通过尝试建立TCP连接来检测端口开放状态
        """
        open_ports = []
        start_time = datetime.now()
        total_ports = len(ports)
        scanned_ports = 0

        # 工作线程函数
        def worker():
            nonlocal scanned_ports
            while port_queue and not self.stop_scan:
                port = port_queue.pop(0)
                try:
                    # 创建TCP socket
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        # 设置连接超时
                        s.settimeout(timeout)

                        # 尝试建立TCP连接（完成三次握手）
                        result = s.connect_ex((target, port))

                        # 如果连接成功（三次握手完成）
                        if result == 0:
                            open_ports.append(port)
                            # 更新UI显示开放端口
                            self.root.after(0, self.update_result, port, "开放")

                            # 关闭连接（发送FIN包）
                            s.shutdown(socket.SHUT_RDWR)
                        else:
                            # 更新UI显示关闭端口
                            self.root.after(0, self.update_result, port, "关闭")
                except socket.timeout:
                    # 连接超时，端口可能关闭或过滤
                    self.root.after(0, self.update_result, port, "超时")
                except Exception as e:
                    # 其他异常
                    self.root.after(0, self.update_result, port, f"错误: {str(e)}")

                # 更新计数
                scanned_ports += 1

                # 限制UI更新频率
                current_time = time.time()
                if current_time - self.last_update > 0.1:  # 每0.1秒更新一次
                    progress = (scanned_ports / total_ports) * 100
                    self.root.after(0, self.update_progress, progress, scanned_ports, total_ports, len(open_ports))
                    self.last_update = current_time

        # 创建工作线程
        port_queue = ports.copy()
        threads = []

        # 创建并启动工作线程
        for _ in range(min(max_threads, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # 等待所有线程完成
        for t in threads:
            t.join()

        # 确保进度完成
        self.root.after(0, self.update_progress, 100, total_ports, total_ports, len(open_ports))

        # 扫描完成
        self.scanning = False
        self.root.after(0, self.scan_completed, open_ports, start_time)

    def update_progress(self, progress, scanned, total, open_count):
        """更新进度条和统计信息"""
        self.progress["value"] = progress
        self.result_stats.config(text=f"扫描进度: {scanned}/{total} 端口 | 开放端口: {open_count}")

    def update_result(self, port, status):
        """更新结果文本框"""
        self.result_text.config(state=tk.NORMAL)

        # 获取端口服务名称
        try:
            service = socket.getservbyport(port)
        except:
            service = "未知服务"

        # 根据状态添加不同颜色的结果
        if status == "开放":
            result_line = f"[✓] 端口 {port:<5} 开放 | 服务: {service}\n"
            self.result_text.insert(tk.END, result_line, "open")
        elif status == "关闭":
            result_line = f"[✗] 端口 {port:<5} 关闭\n"
            self.result_text.insert(tk.END, result_line, "closed")
        elif "超时" in status:
            result_line = f"[⌛] 端口 {port:<5} 连接超时\n"
            self.result_text.tag_config("timeout", foreground="#f39c12")
            self.result_text.insert(tk.END, result_line, "timeout")
        else:
            result_line = f"[⚠] 端口 {port:<5} {status}\n"
            self.result_text.tag_config("error", foreground="#e74c3c")
            self.result_text.insert(tk.END, result_line, "error")

        # 自动滚动到底部
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def scan_completed(self, open_ports, start_time):
        """扫描完成处理"""
        self.scan_btn.config(text="开始扫描")

        duration = datetime.now() - start_time
        self.status_var.set(f"扫描完成! 发现 {len(open_ports)} 个开放端口 | 耗时: {duration.total_seconds():.2f}秒")

        # 添加总结
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, "\n" + "=" * 60 + "\n", "summary")
        self.result_text.insert(tk.END, "扫描总结:\n", "summary")
        self.result_text.insert(tk.END, f"- 目标地址: {self.target_entry.get()}\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描端口数: {len(self.get_port_list())}\n", "summary")
        self.result_text.insert(tk.END, f"- 开放端口数: {len(open_ports)}\n", "summary")
        self.result_text.insert(tk.END, f"- 扫描耗时: {duration.total_seconds():.2f}秒\n", "summary")
        self.result_text.insert(tk.END, "=" * 60 + "\n", "summary")
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

        # 更新结果统计
        self.result_stats.config(text=f"扫描完成 | 开放端口: {len(open_ports)}")


if __name__ == "__main__":
    root = tk.Tk()
    # 设置窗口图标
    try:
        root.iconbitmap("scanner_icon.ico")
    except:
        pass

    app = PortScannerApp(root)
    root.mainloop()