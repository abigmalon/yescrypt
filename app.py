#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Yescrypt密码破解工具 - Flask Web应用
"""

from flask import Flask, render_template, request, jsonify
import yescrypt
import os
import threading

app = Flask(__name__)

# 全局变量存储破解进度
crack_progress = {
    'current': 0,
    'total': 0,
    'current_password': '',
    'status': 'idle',  # idle, running, completed, error
    'result': None
}

rainbow_progress = {
    'current': 0,
    'total': 0,
    'status': 'idle',
    'result': None
}


def update_crack_progress(current, total, password):
    """更新破解进度"""
    crack_progress['current'] = current
    crack_progress['total'] = total
    crack_progress['current_password'] = password


def update_rainbow_progress(current, total):
    """更新彩虹表生成进度"""
    rainbow_progress['current'] = current
    rainbow_progress['total'] = total


@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')


@app.route('/api/shadow/read', methods=['GET'])
def read_shadow():
    """读取shadow文件"""
    shadow_file = request.args.get('file', 'shadow.txt')
    
    try:
        entries = yescrypt.read_shadow_file(shadow_file)
        if not entries:
            return jsonify({
                'success': False,
                'message': f'shadow文件 {shadow_file} 为空或不存在'
            }), 404
        
        # 返回所有条目（支持多个）
        entries_data = []
        for username, full_hash in entries:
            hash_info = yescrypt.analyze_hash_structure(full_hash)
            entries_data.append({
                'username': username,
                'hash': full_hash,
                'hash_info': hash_info
            })
        
        return jsonify({
            'success': True,
            'entries': entries_data,
            'count': len(entries),
            'message': f'成功读取shadow文件，找到 {len(entries)} 个条目'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'读取shadow文件失败: {str(e)}'
        }), 500


@app.route('/api/crack/start', methods=['POST'])
def start_crack():
    """开始破解密码"""
    global crack_progress
    
    data = request.json
    dict_file = data.get('dict_file', 'dict.txt')
    shadow_file = data.get('shadow_file', 'shadow.txt')
    
    # 检查文件是否存在
    if not os.path.exists(dict_file):
        return jsonify({
            'success': False,
            'message': f'字典文件 {dict_file} 不存在'
        }), 400
    
    if not os.path.exists(shadow_file):
        return jsonify({
            'success': False,
            'message': f'shadow文件 {shadow_file} 不存在'
        }), 400
    
    # 读取shadow文件
    entries = yescrypt.read_shadow_file(shadow_file)
    if not entries:
        return jsonify({
            'success': False,
            'message': f'shadow文件 {shadow_file} 为空'
        }), 400
    
    # 使用第一个条目进行破解（可以后续扩展支持选择特定用户）
    username, target_hash = entries[0]
    
    # 重置进度
    crack_progress = {
        'current': 0,
        'total': 0,
        'current_password': '',
        'status': 'running',
        'result': None
    }
    
    # 在后台线程中执行破解
    def crack_thread():
        try:
            result = yescrypt.crack_password(
                target_hash,
                dict_file,
                progress_callback=update_crack_progress
            )
            crack_progress['status'] = 'completed'
            crack_progress['result'] = result
            crack_progress['result']['username'] = username
        except Exception as e:
            crack_progress['status'] = 'error'
            crack_progress['result'] = {
                'success': False,
                'message': f'破解过程出错: {str(e)}'
            }
    
    thread = threading.Thread(target=crack_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': '破解任务已启动'
    })


@app.route('/api/crack/progress', methods=['GET'])
def get_crack_progress():
    """获取破解进度"""
    return jsonify(crack_progress)


@app.route('/api/rainbow/generate', methods=['POST'])
def generate_rainbow():
    """生成彩虹表"""
    global rainbow_progress
    
    data = request.json
    dict_file = data.get('dict_file', 'dict.txt')
    shadow_file = data.get('shadow_file', 'shadow.txt')
    rainbow_file = data.get('rainbow_file', 'rainbow.txt')
    
    # 检查文件是否存在
    if not os.path.exists(dict_file):
        return jsonify({
            'success': False,
            'message': f'字典文件 {dict_file} 不存在'
        }), 400
    
    if not os.path.exists(shadow_file):
        return jsonify({
            'success': False,
            'message': f'shadow文件 {shadow_file} 不存在'
        }), 400
    
    # 读取shadow文件获取salt
    entries = yescrypt.read_shadow_file(shadow_file)
    if not entries:
        return jsonify({
            'success': False,
            'message': f'shadow文件 {shadow_file} 为空'
        }), 400
    
    # 使用第一个条目获取salt（可以后续扩展支持选择特定用户）
    username, target_hash = entries[0]
    salt = yescrypt.extract_salt_from_hash(target_hash)
    
    # 重置进度
    rainbow_progress = {
        'current': 0,
        'total': 0,
        'status': 'running',
        'result': None
    }
    
    # 在后台线程中生成彩虹表
    def rainbow_thread():
        try:
            result = yescrypt.generate_rainbow_table(
                dict_file,
                salt,
                rainbow_file,
                progress_callback=update_rainbow_progress
            )
            rainbow_progress['status'] = 'completed'
            rainbow_progress['result'] = result
        except Exception as e:
            rainbow_progress['status'] = 'error'
            rainbow_progress['result'] = {
                'success': False,
                'message': f'生成彩虹表出错: {str(e)}'
            }
    
    thread = threading.Thread(target=rainbow_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': '彩虹表生成任务已启动'
    })


@app.route('/api/rainbow/progress', methods=['GET'])
def get_rainbow_progress():
    """获取彩虹表生成进度"""
    return jsonify(rainbow_progress)


@app.route('/api/shadow/read-system', methods=['POST'])
def read_system_shadow():
    """从系统读取shadow文件并写入本地"""
    data = request.json or {}
    output_file = data.get('output_file', 'shadow.txt')
    
    try:
        result = yescrypt.read_system_shadow(output_file)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'count': 0,
            'message': f'读取系统shadow文件失败: {str(e)}',
            'entries': []
        }), 500


@app.route('/api/dict/generate', methods=['POST'])
def generate_dict():
    """生成密码字典文件"""
    data = request.json or {}
    
    length = data.get('length', 4)
    use_digits = data.get('use_digits', True)
    use_letters = data.get('use_letters', True)
    use_special = data.get('use_special', False)
    custom_charset = data.get('custom_charset', None)
    output_file = data.get('output_file', 'dict.txt')
    
    # 验证参数
    if not isinstance(length, int) or length < 4 or length > 6:
        return jsonify({
            'success': False,
            'count': 0,
            'message': '密码长度必须在4-6位之间',
            'output_file': ''
        }), 400
    
    # 验证自定义字符集
    if custom_charset:
        if not isinstance(custom_charset, str) or len(custom_charset.strip()) == 0:
            return jsonify({
                'success': False,
                'count': 0,
                'message': '自定义字符集不能为空',
                'output_file': ''
            }), 400
    
    try:
        result = yescrypt.generate_password_dict(
            length=length,
            use_digits=use_digits,
            use_letters=use_letters,
            use_special=use_special,
            custom_charset=custom_charset,
            output_file=output_file
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'count': 0,
            'message': f'生成密码字典失败: {str(e)}',
            'output_file': ''
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

