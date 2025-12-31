# Yescrypt密码破解工具

一个用于破解Kali Linux系统中shadow文件密码的Web应用工具，支持yescrypt算法。

## 功能特性

- 🌈 **彩虹表生成**：将字典中的密码加密后生成彩虹表
- 🔓 **密码破解**：使用字典文件进行暴力破解
- 📊 **实时进度显示**：实时显示破解和生成进度
- 🎨 **现代化Web界面**：美观易用的前端界面
- 📁 **文件管理**：支持自定义字典文件和shadow文件路径

## 系统要求

- Python 3.6+
- Kali Linux 或支持crypt库的Linux系统
- Flask框架

## 安装步骤

1. 安装Python依赖：
```bash
pip3 install -r requirements.txt
```

2. 准备文件：
   - `dict.txt`: 字典文件，每行一个密码
   - `shadow.txt`: shadow文件，包含要破解的用户信息（目前仅支持一个条目）

3. 运行应用：
```bash
python3 app.py
```

4. 打开浏览器访问：
```
http://localhost:5000
```

## 文件说明

- `app.py`: Flask Web应用主程序
- `yescrypt.py`: 核心破解逻辑模块
- `templates/index.html`: 前端界面
- `dict.txt`: 默认字典文件
- `shadow.txt`: shadow文件（从/etc/shadow复制）
- `rainbow.txt`: 生成的彩虹表文件

## 使用方法

1. **读取Shadow信息**：
   - 在配置区域设置shadow文件路径（默认：shadow.txt）
   - 点击"读取Shadow信息"按钮
   - 系统会显示用户信息和哈希结构分析

2. **生成彩虹表**：
   - 设置字典文件路径（默认：dict.txt）
   - 点击"生成彩虹表"按钮
   - 系统会将字典中的所有密码加密并保存到rainbow.txt

3. **破解密码**：
   - 确保已读取shadow信息
   - 点击"开始破解"按钮
   - 系统会使用字典文件逐个尝试密码
   - 实时显示破解进度和当前尝试的密码
   - 破解成功后会显示密码明文

## Shadow文件格式

shadow.txt文件格式示例：
```
mykali:$y$j9T$Re.XWwY8WNOVAJ2PN5B1Y/$32gu9oQ4g8/amXEOEJ7LZ6sXqU1piTfgzmYRhvTqGTD:19980:0:99999:7:::
```

格式：`用户名:哈希值:其他字段...`

## API接口

### GET /api/shadow/read
读取shadow文件信息
- 参数：`file` (可选，默认shadow.txt)

### POST /api/crack/start
开始破解密码
- Body: `{"dict_file": "dict.txt", "shadow_file": "shadow.txt"}`

### GET /api/crack/progress
获取破解进度

### POST /api/rainbow/generate
生成彩虹表
- Body: `{"dict_file": "dict.txt", "shadow_file": "shadow.txt", "rainbow_file": "rainbow.txt"}`

### GET /api/rainbow/progress
获取彩虹表生成进度

## 注意事项

- 目前仅支持yescrypt算法（$y$开头的哈希）
- shadow文件目前仅支持一个条目
- 字典文件应使用UTF-8编码
- 破解时间取决于字典文件大小和密码复杂度

## 许可证

本项目仅供学习和研究使用。

