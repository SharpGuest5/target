import tkinter as tk
from tkinter import messagebox


class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("登录系统")
        self.root.geometry("350x220")  # 稍微加宽以适应新按钮
        self.root.resizable(False, False)

        # 设置界面居中
        window_width = 350
        window_height = 220
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # 创建界面元素
        self.create_widgets()

        # 预设的账号密码
        self.valid_credentials = {
            "admin": "admin123",
            "user": "password123",
            "test": "test123"
        }

        # 记住密码
        self.remember_var = tk.BooleanVar()
        self.remember_check = tk.Checkbutton(
            self.button_frame,
            text="记住密码",
            variable=self.remember_var
        )
        self.remember_check.pack(pady=5)

    def create_widgets(self):
        # 标题标签
        self.title_label = tk.Label(
            self.root,
            text="用户登录",
            font=("Microsoft YaHei", 16, "bold")
        )
        self.title_label.pack(pady=10)

        # 账号框架
        self.username_frame = tk.Frame(self.root)
        self.username_frame.pack(fill="x", padx=30, pady=5)

        self.username_label = tk.Label(
            self.username_frame,
            text="账号:",
            width=8,
            anchor="e"
        )
        self.username_label.pack(side="left")

        self.username_entry = tk.Entry(
            self.username_frame,
            width=20
        )
        self.username_entry.pack(side="left", padx=5)
        self.username_entry.focus()  # 初始焦点

        # 密码框架
        self.password_frame = tk.Frame(self.root)
        self.password_frame.pack(fill="x", padx=30, pady=5)

        self.password_label = tk.Label(
            self.password_frame,
            text="密码:",
            width=8,
            anchor="e"
        )
        self.password_label.pack(side="left")

        self.password_entry = tk.Entry(
            self.password_frame,
            width=20,
            show="*"  # 密码显示为星号
        )
        self.password_entry.pack(side="left", padx=5)

        # 添加显示/隐藏密码按钮
        self.show_pass_btn = tk.Button(
            self.password_frame,
            text="显示",
            width=4,
            command=self.toggle_password
        )
        self.show_pass_btn.pack(side="left", padx=(0, 0))
        self.password_hidden = True  # 初始状态为隐藏密码

        # 登录按钮框架
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=15)

        self.login_button = tk.Button(
            self.button_frame,
            text="登录",
            width=10,
            command=self.attempt_login
        )
        self.login_button.pack()

        # 绑定回车键
        self.root.bind('<Return>', lambda event: self.attempt_login())

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
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning("输入错误", "账号和密码不能为空")
            return

        # 验证账号密码
        if username in self.valid_credentials and password == self.valid_credentials[username]:
            messagebox.showinfo("登录成功", f"欢迎回来, {username}!")
            # 这里添加登录成功后的操作
        else:
            messagebox.showerror("登录失败", "账号或密码错误")
            self.password_entry.delete(0, tk.END)  # 清空密码框


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
