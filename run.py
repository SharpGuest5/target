import tkinter as tk
from tkinter import messagebox, ttk
import json
import os
import hashlib
import subprocess  # 用于运行外部模块
import sys  # 用于获取当前文件路径


class UserSystem:
    """用户管理系统"""
    USER_DATA_FILE = "users.json"

    @staticmethod
    def _hash_password(password):
        """使用SHA-256哈希算法加密密码"""
        return hashlib.sha256(password.encode()).hexdigest()

    @classmethod
    def load_users(cls):
        """从文件加载用户数据"""
        if not os.path.exists(cls.USER_DATA_FILE):
            return {}

        try:
            with open(cls.USER_DATA_FILE, "r") as f:
                return json.load(f)
        except:
            return {}

    @classmethod
    def save_users(cls, users):
        """保存用户数据到文件"""
        with open(cls.USER_DATA_FILE, "w") as f:
            json.dump(users, f, indent=2)

    @classmethod
    def register_user(cls, username, password, email):
        """注册新用户"""
        users = cls.load_users()

        # 检查用户名是否已存在
        if username in users:
            return False, "用户名已存在"

        # 检查邮箱是否已被使用
        for user_data in users.values():
            if user_data["email"] == email:
                return False, "该邮箱已被注册"

        # 创建新用户
        users[username] = {
            "password": cls._hash_password(password),
            "email": email,
            "remember_password": False
        }

        cls.save_users(users)
        return True, "注册成功"

    @classmethod
    def authenticate(cls, identifier, password):
        """验证用户登录"""
        users = cls.load_users()

        # 尝试通过用户名登录
        if identifier in users:
            user_data = users[identifier]
            if user_data["password"] == cls._hash_password(password):
                return True, identifier, user_data["email"]

        # 尝试通过邮箱登录
        for username, user_data in users.items():
            if user_data["email"] == identifier:
                if user_data["password"] == cls._hash_password(password):
                    return True, username, user_data["email"]

        return False, None, None


class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("登录系统")
        self.current_process = None  # 存储当前运行的子进程

        # 设置最小窗口尺寸
        self.root.minsize(400, 300)

        # 设置初始窗口大小（可自适应）
        width = 450
        height = 320
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        root.geometry(f"{width}x{height}+{x}+{y}")

        # 配置网格布局权重
        self.configure_grid()

        # 创建主框架
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        # 创建登录界面
        self.create_login_ui()

        # 加载用户数据
        self.users = UserSystem.load_users()

    def configure_grid(self):
        """配置网格布局权重"""
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def create_login_ui(self):
        """创建登录界面"""
        # 清除主框架内容
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # 配置主框架网格
        self.main_frame.grid_rowconfigure(0, weight=1)  # 顶部空白
        self.main_frame.grid_rowconfigure(1, weight=0)  # 标题
        self.main_frame.grid_rowconfigure(2, weight=0)  # 标识符
        self.main_frame.grid_rowconfigure(3, weight=0)  # 密码
        self.main_frame.grid_rowconfigure(4, weight=0)  # 记住密码
        self.main_frame.grid_rowconfigure(5, weight=0)  # 按钮
        self.main_frame.grid_rowconfigure(6, weight=0)  # 注册链接
        self.main_frame.grid_rowconfigure(7, weight=1)  # 底部空白

        self.main_frame.grid_columnconfigure(0, weight=1)  # 左侧空白
        self.main_frame.grid_columnconfigure(1, weight=0)  # 标签列
        self.main_frame.grid_columnconfigure(2, weight=0)  # 输入框列
        self.main_frame.grid_columnconfigure(3, weight=0)  # 按钮列
        self.main_frame.grid_columnconfigure(4, weight=1)  # 右侧空白

        # 标题标签
        self.title_label = ttk.Label(
            self.main_frame,
            text="用户登录",
            font=("Microsoft YaHei", 16, "bold")
        )
        self.title_label.grid(row=1, column=1, columnspan=3, pady=(10, 20), sticky="n")

        # 标识符标签
        self.identifier_label = ttk.Label(
            self.main_frame,
            text="账号/邮箱:",
            font=("Microsoft YaHei", 11)
        )
        self.identifier_label.grid(row=2, column=1, padx=(0, 5), pady=5, sticky="e")

        # 标识符输入框
        self.identifier_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25
        )
        self.identifier_entry.grid(row=2, column=2, padx=(0, 5), pady=5, sticky="ew")
        self.identifier_entry.focus()  # 初始焦点

        # 密码标签
        self.password_label = ttk.Label(
            self.main_frame,
            text="密码:",
            font=("Microsoft YaHei", 11)
        )
        self.password_label.grid(row=3, column=1, padx=(0, 5), pady=5, sticky="e")

        # 密码输入框
        self.password_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25,
            show="*"  # 密码显示为星号
        )
        self.password_entry.grid(row=3, column=2, padx=(0, 5), pady=5, sticky="ew")

        # 显示/隐藏密码按钮
        self.show_pass_btn = ttk.Button(
            self.main_frame,
            text="显示",
            width=6,
            command=self.toggle_password
        )
        self.show_pass_btn.grid(row=3, column=3, padx=(0, 10), sticky="w")
        self.password_hidden = True  # 初始状态为隐藏密码

        # 记住密码复选框
        self.remember_var = tk.BooleanVar(value=False)
        self.remember_check = ttk.Checkbutton(
            self.main_frame,
            text="记住密码",
            variable=self.remember_var
        )
        self.remember_check.grid(row=4, column=2, pady=(5, 0), sticky="w")

        # 登录按钮
        self.login_button = ttk.Button(
            self.main_frame,
            text="登录",
            width=12,
            command=self.attempt_login
        )
        self.login_button.grid(row=5, column=1, columnspan=3, pady=(15, 10), sticky="n")

        # 注册链接
        self.register_link = ttk.Label(
            self.main_frame,
            text="没有账号？立即注册",
            font=("Microsoft YaHei", 9, "underline"),
            foreground="blue",
            cursor="hand2"
        )
        self.register_link.grid(row=6, column=1, columnspan=3, pady=(5, 15))
        self.register_link.bind("<Button-1>", lambda e: self.show_register_ui())

        # 配置列权重
        self.main_frame.grid_columnconfigure(2, weight=1, minsize=180)

        # 绑定回车键
        self.root.bind('<Return>', lambda event: self.attempt_login())

    def show_register_ui(self):
        """显示注册界面"""
        # 清除主框架内容
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # 配置主框架网格
        self.main_frame.grid_rowconfigure(0, weight=1)  # 顶部空白
        self.main_frame.grid_rowconfigure(1, weight=0)  # 标题
        self.main_frame.grid_rowconfigure(2, weight=0)  # 用户名
        self.main_frame.grid_rowconfigure(3, weight=0)  # 密码
        self.main_frame.grid_rowconfigure(4, weight=0)  # 确认密码
        self.main_frame.grid_rowconfigure(5, weight=0)  # 邮箱
        self.main_frame.grid_rowconfigure(6, weight=0)  # 按钮
        self.main_frame.grid_rowconfigure(7, weight=0)  # 返回登录
        self.main_frame.grid_rowconfigure(8, weight=1)  # 底部空白

        self.main_frame.grid_columnconfigure(0, weight=1)  # 左侧空白
        self.main_frame.grid_columnconfigure(1, weight=0)  # 标签列
        self.main_frame.grid_columnconfigure(2, weight=0)  # 输入框列
        self.main_frame.grid_columnconfigure(3, weight=1)  # 右侧空白

        # 标题标签
        self.title_label = ttk.Label(
            self.main_frame,
            text="用户注册",
            font=("Microsoft YaHei", 16, "bold")
        )
        self.title_label.grid(row=1, column=1, columnspan=2, pady=(10, 20), sticky="n")

        # 用户名标签
        self.username_label = ttk.Label(
            self.main_frame,
            text="用户名:",
            font=("Microsoft YaHei", 11)
        )
        self.username_label.grid(row=2, column=1, padx=(0, 5), pady=5, sticky="e")

        # 用户名输入框
        self.username_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25
        )
        self.username_entry.grid(row=2, column=2, padx=(0, 5), pady=5, sticky="ew")
        self.username_entry.focus()

        # 密码标签
        self.password_label = ttk.Label(
            self.main_frame,
            text="密码:",
            font=("Microsoft YaHei", 11)
        )
        self.password_label.grid(row=3, column=1, padx=(0, 5), pady=5, sticky="e")

        # 密码输入框
        self.reg_password_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25,
            show="*"
        )
        self.reg_password_entry.grid(row=3, column=2, padx=(0, 5), pady=5, sticky="ew")

        # 确认密码标签
        self.confirm_label = ttk.Label(
            self.main_frame,
            text="确认密码:",
            font=("Microsoft YaHei", 11)
        )
        self.confirm_label.grid(row=4, column=1, padx=(0, 5), pady=5, sticky="e")

        # 确认密码输入框
        self.confirm_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25,
            show="*"
        )
        self.confirm_entry.grid(row=4, column=2, padx=(0, 5), pady=5, sticky="ew")

        # 邮箱标签
        self.email_label = ttk.Label(
            self.main_frame,
            text="电子邮箱:",
            font=("Microsoft YaHei", 11)
        )
        self.email_label.grid(row=5, column=1, padx=(0, 5), pady=5, sticky="e")

        # 邮箱输入框
        self.email_entry = ttk.Entry(
            self.main_frame,
            font=("Microsoft YaHei", 11),
            width=25
        )
        self.email_entry.grid(row=5, column=2, padx=(0, 5), pady=5, sticky="ew")

        # 注册按钮
        self.register_button = ttk.Button(
            self.main_frame,
            text="注册",
            width=12,
            command=self.attempt_register
        )
        self.register_button.grid(row=6, column=1, columnspan=2, pady=(15, 10), sticky="n")

        # 返回登录链接
        self.back_link = ttk.Label(
            self.main_frame,
            text="返回登录",
            font=("Microsoft YaHei", 9, "underline"),
            foreground="blue",
            cursor="hand2"
        )
        self.back_link.grid(row=7, column=1, columnspan=2, pady=(5, 15))
        self.back_link.bind("<Button-1>", lambda e: self.create_login_ui())

        # 配置列权重
        self.main_frame.grid_columnconfigure(2, weight=1, minsize=180)

        # 绑定回车键
        self.root.bind('<Return>', lambda event: self.attempt_register())

    def toggle_password(self):
        """切换密码显示/隐藏状态"""
        if self.password_hidden:
            self.password_entry.config(show="")
            self.show_pass_btn.config(text="隐藏")
            self.password_hidden = False
        else:
            self.password_entry.config(show="*")
            self.show_pass_btn.config(text="显示")
            self.password_hidden = True

    def attempt_login(self):
        """尝试登录"""
        identifier = self.identifier_entry.get().strip()
        password = self.password_entry.get().strip()

        if not identifier or not password:
            messagebox.showwarning("输入错误", "账号/邮箱和密码不能为空")
            return

        # 验证用户
        success, username, email = UserSystem.authenticate(identifier, password)

        if success:
            # 登录成功后显示主功能界面
            self.show_main_menu(username)

            # 记住密码功能
            if self.remember_var.get():
                # 实际应用中应安全存储
                print(f"记住密码：用户名={username}")
        else:
            messagebox.showerror("登录失败", "账号/邮箱或密码错误")
            self.password_entry.delete(0, tk.END)  # 清空密码框

    def show_main_menu(self, username):
        """显示主功能菜单界面"""
        # 清除主框架内容
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # 更新窗口标题
        self.root.title(f"安全工具箱 - 欢迎 {username}")

        # 配置主框架网格
        self.main_frame.grid_rowconfigure(0, weight=0)  # 欢迎信息
        self.main_frame.grid_rowconfigure(1, weight=0)  # 分隔线
        self.main_frame.grid_rowconfigure(2, weight=0)  # 模块标题
        self.main_frame.grid_rowconfigure(3, weight=1)  # 模块按钮区域
        self.main_frame.grid_rowconfigure(4, weight=0)  # 底部按钮
        self.main_frame.grid_columnconfigure(0, weight=1)  # 左侧空白
        self.main_frame.grid_columnconfigure(1, weight=0)  # 内容列
        self.main_frame.grid_columnconfigure(2, weight=1)  # 右侧空白

        # 欢迎信息
        welcome_label = ttk.Label(
            self.main_frame,
            text=f"欢迎回来, {username}!",
            font=("Microsoft YaHei", 14, "bold"),
            foreground="#4A90E2"
        )
        welcome_label.grid(row=0, column=1, pady=(20, 10), sticky="n")

        # 分隔线
        ttk.Separator(self.main_frame, orient="horizontal").grid(
            row=1, column=1, sticky="ew", pady=10, padx=20
        )

        # 模块标题
        module_title = ttk.Label(
            self.main_frame,
            text="安全工具模块",
            font=("Microsoft YaHei", 12, "bold")
        )
        module_title.grid(row=2, column=1, pady=(10, 20))

        # 模块按钮框架
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=1, sticky="nsew")

        # 配置按钮框架网格
        for i in range(4):  # 4行按钮
            button_frame.grid_rowconfigure(i, weight=1, pad=10)
        for i in range(3):  # 3列按钮
            button_frame.grid_columnconfigure(i, weight=1, pad=15)

        # 创建模块按钮
        modules = [
            {"name": "域名检测", "command": self.run_domain_detection, "icon": "🌐"},
            {"name": "端口扫描", "command": lambda: self.show_module_message("端口扫描"), "icon": "🔍"},
            {"name": "漏洞扫描", "command": lambda: self.show_module_message("漏洞扫描"), "icon": "🛡️"},
            {"name": "日志分析", "command": lambda: self.show_module_message("日志分析"), "icon": "📊"},
            {"name": "网络监控", "command": lambda: self.show_module_message("网络监控"), "icon": "📶"},
            {"name": "加密工具", "command": lambda: self.show_module_message("加密工具"), "icon": "🔒"},
        ]

        # 添加按钮到界面
        for i, module in enumerate(modules):
            row = i // 3
            col = i % 3

            btn = tk.Button(
                button_frame,
                text=f"{module['icon']} {module['name']}",
                font=("Microsoft YaHei", 11),
                bg="#4A90E2",
                fg="white",
                relief="flat",
                padx=20,
                pady=15,
                command=module["command"],
                cursor="hand2"
            )
            btn.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)

            # 添加悬停效果
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#357ABD"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#4A90E2"))

        # 底部按钮区域
        bottom_frame = ttk.Frame(self.main_frame)
        bottom_frame.grid(row=4, column=1, sticky="ew", pady=(30, 20))
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=0)
        bottom_frame.grid_columnconfigure(2, weight=1)

        # 注销按钮
        logout_btn = ttk.Button(
            bottom_frame,
            text="注销",
            width=10,
            command=self.create_login_ui
        )
        logout_btn.grid(row=0, column=1, padx=10)

        # 退出按钮
        exit_btn = ttk.Button(
            bottom_frame,
            text="退出系统",
            width=10,
            command=self.root.destroy
        )
        exit_btn.grid(row=0, column=1, padx=10, pady=(10, 0))

    def run_domain_detection(self):
        """运行域名检测模块"""
        try:
            # 获取当前脚本所在目录
            current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            domain_detection_path = os.path.join(current_dir, "DomainDetection.py")

            # 检查文件是否存在
            if not os.path.exists(domain_detection_path):
                messagebox.showerror("错误", f"找不到模块文件: {domain_detection_path}")
                return

            # 终止当前运行的进程（如果有）
            if self.current_process:
                try:
                    self.current_process.terminate()
                except:
                    pass

            # 使用子进程运行模块
            self.current_process = subprocess.Popen([sys.executable, domain_detection_path])
            messagebox.showinfo("启动成功", "域名检测模块已启动，请查看控制台窗口")
        except Exception as e:
            messagebox.showerror("错误", f"启动模块失败: {str(e)}")

    def show_module_message(self, module_name):
        """显示模块信息（用于未实现的模块）"""
        messagebox.showinfo("模块信息", f"{module_name}模块正在开发中，敬请期待！")

    def attempt_register(self):
        """尝试注册"""
        username = self.username_entry.get().strip()
        password = self.reg_password_entry.get().strip()
        confirm = self.confirm_entry.get().strip()
        email = self.email_entry.get().strip()

        # 验证输入
        if not username or not password or not confirm or not email:
            messagebox.showwarning("输入错误", "所有字段都必须填写")
            return

        if password != confirm:
            messagebox.showwarning("输入错误", "两次输入的密码不一致")
            self.reg_password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)
            self.reg_password_entry.focus()
            return

        if "@" not in email or "." not in email:
            messagebox.showwarning("输入错误", "请输入有效的电子邮箱地址")
            self.email_entry.focus()
            return

        # 注册用户
        success, message = UserSystem.register_user(username, password, email)

        if success:
            messagebox.showinfo("注册成功", message)
            self.create_login_ui()
            # 自动填充新注册的用户名
            self.identifier_entry.insert(0, username)
        else:
            messagebox.showerror("注册失败", message)


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
