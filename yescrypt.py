#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Yescrypt彩虹表破解工具
用于破解Kali Linux系统中使用yescrypt算法加密的密码哈希
"""

import crypt
import sys
import os
import subprocess
import itertools
import string
from typing import Optional, List


def parse_shadow_entry(shadow_line: str) -> tuple:
    """
    解析shadow文件条目，提取用户名和完整哈希值
    
    Args:
        shadow_line: shadow文件中的一行，格式：username:hash:...
    
    Returns:
        tuple: (username, full_hash)
    """
    parts = shadow_line.strip().split(':')
    if len(parts) < 2:
        raise ValueError("无效的shadow文件格式")
    
    username = parts[0]
    full_hash = parts[1]
    
    return username, full_hash


def extract_salt_from_hash(full_hash: str) -> str:
    """
    从完整哈希中提取salt部分（用于crypt.crypt函数）
    
    yescrypt哈希格式：$y$[rounds]$[salt]$[hash]
    对于crypt.crypt函数，salt应该是：$y$[rounds]$[salt]
    
    Args:
        full_hash: 完整的哈希值，如 $y$j9T$Re.XWwY8WNOVAJ2PN5B1Y/$32gu9oQ4g8/...
    
    Returns:
        str: salt字符串，用于crypt.crypt函数
    """
    # yescrypt哈希格式：$y$[rounds]$[salt]$[hash]
    # 我们需要提取到第三个$之前的部分作为salt
    parts = full_hash.split('$')
    if len(parts) < 4:
        raise ValueError("无效的yescrypt哈希格式")
    
    # 重新组合：$y$[rounds]$[salt]
    salt = '$' + '$'.join(parts[1:4])  # $y$j9T$Re.XWwY8WNOVAJ2PN5B1Y/
    
    return salt


def crack_password(target_hash: str, dict_file: str, progress_callback=None, rainbow_file: str = "rainbow.txt") -> dict:
    """
    使用字典文件破解密码哈希（逻辑：先生成彩虹表，再从彩虹表中查找匹配）
    
    Args:
        target_hash: 目标哈希值（完整哈希）
        dict_file: 字典文件路径
        progress_callback: 进度回调函数，接收(current, total, password)参数
        rainbow_file: 彩虹表文件路径（可选，默认 rainbow.txt）
    
    Returns:
        dict: 包含破解结果的字典
            {
                'success': bool,
                'password': str or None,
                'attempts': int,
                'total': int,
                'message': str
            }
    """
    # 提取salt
    salt = extract_salt_from_hash(target_hash)
    
    # 第一步：生成彩虹表（字典文件+参数 -> 彩虹表文件，包含明文:哈希值）
    rainbow_result = generate_rainbow_table(dict_file, salt, rainbow_file, progress_callback=None)
    
    if not rainbow_result['success']:
        return {
            'success': False,
            'password': None,
            'attempts': 0,
            'total': 0,
            'message': f'生成彩虹表失败: {rainbow_result["message"]}'
        }
    
    # 第二步：从彩虹表中查找匹配的哈希值
    try:
        with open(rainbow_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {
            'success': False,
            'password': None,
            'attempts': 0,
            'total': 0,
            'message': f'错误：找不到彩虹表文件 {rainbow_file}'
        }
    except Exception as e:
        return {
            'success': False,
            'password': None,
            'attempts': 0,
            'total': 0,
            'message': f'错误：无法读取彩虹表文件: {e}'
        }
    
    # 过滤掉注释行和空行
    valid_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    total = len(valid_lines)
    
    # 遍历彩虹表中的每一行，比对哈希值
    for index, line in enumerate(valid_lines, 1):
        try:
            # 解析格式：明文:哈希值
            parts = line.strip().split(':', 1)  # 只分割第一个冒号
            if len(parts) != 2:
                continue
            
            password = parts[0]
            rainbow_hash = parts[1]
            
            # 调用进度回调
            if progress_callback:
                progress_callback(index, total, password)
            
            # 比对哈希值，找到匹配则返回密码明文
            if rainbow_hash == target_hash:
                return {
                    'success': True,
                    'password': password,
                    'attempts': index,
                    'total': total,
                    'message': f'密码破解成功！尝试次数: {index}'
                }
        except Exception:
            continue
    
    return {
        'success': False,
        'password': None,
        'attempts': total,
        'total': total,
        'message': f'彩虹表查找失败，未找到匹配的密码（已检查 {total} 条记录）'
    }


def generate_rainbow_table(dict_file: str, salt: str, rainbow_file: str = "rainbow.txt", progress_callback=None):
    """
    生成彩虹表：将字典中的密码加密后写入文件
    
    Args:
        dict_file: 字典文件路径
        salt: salt字符串（用于crypt.crypt函数）
        rainbow_file: 彩虹表输出文件路径
        progress_callback: 进度回调函数，接收(current, total)参数
    
    Returns:
        dict: 包含生成结果的字典
            {
                'success': bool,
                'count': int,
                'message': str
            }
    """
    try:
        with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = f.readlines()
    except FileNotFoundError:
        return {
            'success': False,
            'count': 0,
            'message': f'错误：找不到字典文件 {dict_file}'
        }
    except Exception as e:
        return {
            'success': False,
            'count': 0,
            'message': f'错误：无法读取字典文件: {e}'
        }
    
    total = len(passwords)
    success_count = 0
    
    # 打开彩虹表文件进行写入
    try:
        with open(rainbow_file, 'w', encoding='utf-8') as f:
            # 写入文件头
            f.write("# 彩虹表 - 密码明文与哈希值对应表\n")
            f.write("# 格式: 明文:哈希值\n")
            f.write(f"# Salt: {salt}\n")
            f.write("# " + "=" * 50 + "\n\n")
            
            # 遍历字典中的每个密码
            for index, password in enumerate(passwords, 1):
                password = password.strip()
                if not password:
                    continue
                
                try:
                    # 使用crypt库生成哈希
                    generated_hash = crypt.crypt(password, salt)
                    
                    # 写入彩虹表：格式为 明文:哈希值
                    f.write(f"{password}:{generated_hash}\n")
                    success_count += 1
                    
                    # 调用进度回调
                    if progress_callback:
                        progress_callback(index, total)
                        
                except Exception as e:
                    continue
        
        return {
            'success': True,
            'count': success_count,
            'message': f'彩虹表生成完成！成功生成 {success_count} 条记录，文件已保存到: {rainbow_file}'
        }
        
    except Exception as e:
        return {
            'success': False,
            'count': 0,
            'message': f'错误：无法写入彩虹表文件: {e}'
        }


def analyze_hash_structure(full_hash: str) -> dict:
    """
    分析哈希结构，解释各个部分
    
    Args:
        full_hash: 完整的哈希值
    
    Returns:
        dict: 包含哈希结构信息的字典
    """
    parts = full_hash.split('$')
    
    result = {
        'algorithm': '',
        'rounds': '',
        'salt': '',
        'hash': '',
        'full_salt': ''
    }
    
    if len(parts) >= 4:
        algorithm = parts[1]  # y
        rounds = parts[2]     # j9T
        salt_part = parts[3]  # Re.XWwY8WNOVAJ2PN5B1Y/
        hash_part = parts[4] if len(parts) > 4 else ""
        
        result = {
            'algorithm': f'${algorithm}$ (yescrypt)',
            'rounds': f'{rounds} (base64编码)',
            'salt': f'{salt_part} (base64编码，22字符)',
            'hash': f'{hash_part} (base64编码)',
            'full_salt': f'${algorithm}${rounds}${salt_part}'
        }
    
    return result


def read_shadow_file(shadow_file: str = "shadow.txt") -> list:
    """
    从shadow文件读取条目
    
    Args:
        shadow_file: shadow文件路径
    
    Returns:
        list: shadow条目列表，每个条目为(username, full_hash)元组
    """
    entries = []
    try:
        with open(shadow_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        username, full_hash = parse_shadow_entry(line)
                        entries.append((username, full_hash))
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    
    return entries


def read_system_shadow(output_file: str = "shadow.txt") -> dict:
    """
    从系统/etc/shadow文件读取并写入到本地文件（需要管理员权限）
    
    Args:
        output_file: 输出文件路径
    
    Returns:
        dict: 包含操作结果的字典
            {
                'success': bool,
                'count': int,
                'message': str,
                'entries': list  # 成功时包含条目列表
            }
    """
    system_shadow = "/etc/shadow"
    
    # 检查是否有读取权限
    if not os.path.exists(system_shadow):
        return {
            'success': False,
            'count': 0,
            'message': f'系统shadow文件 {system_shadow} 不存在',
            'entries': []
        }
    
    # 尝试直接读取（需要root权限）
    try:
        with open(system_shadow, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except PermissionError:
        # 如果没有权限，尝试使用sudo cat命令
        try:
            result = subprocess.run(
                ['sudo', 'cat', system_shadow],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                return {
                    'success': False,
                    'count': 0,
                    'message': '需要管理员权限（sudo）来读取系统shadow文件。请使用sudo运行程序或确保有读取权限。',
                    'entries': []
                }
            lines = result.stdout.splitlines(True)
        except FileNotFoundError:
            return {
                'success': False,
                'count': 0,
                'message': '无法使用sudo命令，请确保已安装sudo或使用root权限运行',
                'entries': []
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'count': 0,
                'message': '读取系统shadow文件超时',
                'entries': []
            }
        except Exception as e:
            return {
                'success': False,
                'count': 0,
                'message': f'读取系统shadow文件失败: {str(e)}',
                'entries': []
            }
    
    # 解析并过滤有效条目
    entries = []
    valid_lines = []
    
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                username, full_hash = parse_shadow_entry(line)
                # 只保存yescrypt算法的条目
                if full_hash.startswith('$y$'):
                    entries.append((username, full_hash))
                    valid_lines.append(line + '\n')
            except ValueError:
                continue
    
    if not entries:
        return {
            'success': False,
            'count': 0,
            'message': '系统shadow文件中没有找到yescrypt算法的条目',
            'entries': []
        }
    
    # 写入到输出文件（如果文件存在则创建副本）
    output_path = output_file
    if os.path.exists(output_path):
        base_name = os.path.splitext(output_path)[0]
        ext = os.path.splitext(output_path)[1]
        counter = 1
        while os.path.exists(f"{base_name}_{counter}{ext}"):
            counter += 1
        output_path = f"{base_name}_{counter}{ext}"
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(valid_lines)
        
        return {
            'success': True,
            'count': len(entries),
            'message': f'成功读取 {len(entries)} 个yescrypt条目，已保存到 {output_path}',
            'entries': entries,
            'output_file': output_path
        }
    except Exception as e:
        return {
            'success': False,
            'count': 0,
            'message': f'写入文件失败: {str(e)}',
            'entries': []
        }


def generate_password_dict(length: int, use_digits: bool = True, use_letters: bool = True, 
                          use_special: bool = False, custom_charset: str = None, 
                          output_file: str = "dict.txt") -> dict:
    """
    生成密码字典文件
    
    Args:
        length: 密码长度（4-6位）
        use_digits: 是否使用数字 (0-9) - 当custom_charset为None时生效
        use_letters: 是否使用字母 (a-z, A-Z) - 当custom_charset为None时生效
        use_special: 是否使用特殊字符 (!@#$%^&*()_+-=[]{}|;:,.<>?) - 当custom_charset为None时生效
        custom_charset: 自定义字符集字符串，如果提供则优先使用此字符集
        output_file: 输出文件路径
    
    Returns:
        dict: 包含生成结果的字典
            {
                'success': bool,
                'count': int,
                'message': str,
                'output_file': str
            }
    """
    # 验证长度
    if length < 4 or length > 6:
        return {
            'success': False,
            'count': 0,
            'message': '密码长度必须在4-6位之间',
            'output_file': ''
        }
    
    # 构建字符集
    if custom_charset:
        # 使用用户指定的字符集
        charset = list(custom_charset)
        # 去重并保持顺序
        charset = list(dict.fromkeys(charset))
    else:
        # 使用布尔参数构建字符集
        charset = []
        if use_digits:
            charset.extend(string.digits)  # 0-9
        if use_letters:
            charset.extend(string.ascii_lowercase)  # a-z
            charset.extend(string.ascii_uppercase)  # A-Z
        if use_special:
            charset.extend('!@#$%^&*()_+-=[]{}|;:,.<>?')  # 特殊字符
    
    if not charset:
        return {
            'success': False,
            'count': 0,
            'message': '字符集不能为空，请至少指定一个字符',
            'output_file': ''
        }
    
    # 计算总数量（用于进度显示）
    total = len(charset) ** length
    
    # 如果数量太大，给出警告
    if total > 1000000:  # 超过100万
        return {
            'success': False,
            'count': 0,
            'message': f'生成的密码数量过多（{total}个），请减少长度或字符类型',
            'output_file': ''
        }
    
    # 检查输出文件是否存在，如果存在则创建副本
    output_path = output_file
    if os.path.exists(output_path):
        base_name = os.path.splitext(output_path)[0]
        ext = os.path.splitext(output_path)[1]
        counter = 1
        while os.path.exists(f"{base_name}_{counter}{ext}"):
            counter += 1
        output_path = f"{base_name}_{counter}{ext}"
    
    # 生成所有可能的密码组合
    try:
        count = 0
        with open(output_path, 'w', encoding='utf-8') as f:
            # 使用itertools生成所有组合
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                f.write(password + '\n')
                count += 1
        
        return {
            'success': True,
            'count': count,
            'message': f'成功生成 {count} 个密码，已保存到 {output_path}',
            'output_file': output_path
        }
    except Exception as e:
        return {
            'success': False,
            'count': 0,
            'message': f'生成密码字典失败: {str(e)}',
            'output_file': ''
        }


def main():
    """
    主函数（命令行模式）
    """
    shadow_file = "shadow.txt"
    dict_file = "dict.txt"
    
    print("=" * 60)
    print("Yescrypt彩虹表破解工具")
    print("=" * 60)
    print()
    
    try:
        # 从shadow.txt读取条目
        entries = read_shadow_file(shadow_file)
        if not entries:
            print(f"[!] 错误：无法从 {shadow_file} 读取shadow信息")
            print("[!] 请确保shadow.txt文件存在且包含有效的shadow条目")
            sys.exit(1)
        
        username, target_hash = entries[0]
        print(f"[*] 用户名: {username}")
        print(f"[*] 字典文件: {dict_file}")
        print(f"[*] Shadow文件: {shadow_file}")
        print()
        
        # 分析哈希结构
        hash_info = analyze_hash_structure(target_hash)
        print("=" * 60)
        print("哈希结构分析")
        print("=" * 60)
        print(f"算法标识: {hash_info['algorithm']}")
        print(f"轮数参数: {hash_info['rounds']}")
        print(f"Salt值: {hash_info['salt']}")
        print(f"哈希值: {hash_info['hash']}")
        print(f"\n完整salt（用于crypt.crypt）: {hash_info['full_salt']}")
        print("=" * 60)
        print()
        
        # 提取salt用于生成彩虹表
        salt = extract_salt_from_hash(target_hash)
        
        # 生成彩虹表
        rainbow_file = "rainbow.txt"
        print("\n" + "=" * 60)
        print("生成彩虹表")
        print("=" * 60)
        print()
        rainbow_result = generate_rainbow_table(dict_file, salt, rainbow_file)
        if rainbow_result['success']:
            print(f"[+] {rainbow_result['message']}")
        else:
            print(f"[!] {rainbow_result['message']}")
        
        print("\n" + "=" * 60)
        print("开始破解密码")
        print("=" * 60)
        print()
        
        # 执行破解
        def progress_callback(current, total, password):
            if current % 10 == 0 or current == total:
                print(f"[*] 尝试第 {current}/{total} 个密码: {password}")
        
        result = crack_password(target_hash, dict_file, progress_callback=progress_callback)
        
        if result['success']:
            print("\n" + "=" * 60)
            print("破解结果")
            print("=" * 60)
            print(f"用户名: {username}")
            print(f"密码: {result['password']}")
            print(f"尝试次数: {result['attempts']}")
            print("=" * 60)
        else:
            print(f"\n[-] {result['message']}")
            print("\n建议：")
            print("1. 检查字典文件是否包含正确的密码")
            print("2. 尝试使用更大的字典文件")
            print("3. 确认哈希值格式正确")
            
    except Exception as e:
        print(f"[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

