# @             Project: BuaaProxy -> BuaaProxy.py
# @              Author: WangNan
# @       Creation Date: 2025/11/1 23:15
# @         Description: BUAA campus network self-built proxy, used to access on-campus services
# @ Version Information: Created by WangNan, 2025/11/1
#                        Revised by WangNan, 2025/11/4, add robots()
#                        Revised by WangNan, 2025/11/4, add get_client_ip() and favicon()
#                        Revised by WangNan, 2026/3/24, add 36000 for cache bug
#                        Revised by WangNan, 2026/4/11, add -3000 for signing failure bug
#                        Revised by WangNan, 2026/4/16, add UA, and remove -3000
#                        Revised by WangNan, 2026/4/18, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/5/10, add timestamp_url
#                        Revised by WangNan, 2026/5/14, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/5/20, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/6/3,  changed the login method to username and password,
#                                                       added several functions such as sso(),
#                                                       and restructured the overall code architecture
# =============================================================================================================


import os
import re
import time
import base64
import requests
import logging
import urllib3

from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_from_directory
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

file_handler = logging.FileHandler('BuaaProxy.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEYS = os.environ.get('BUAA_PROXY_API_KEY').split(',')

WHITELIST_STUDENT_IDS = {
}

BLACKLIST_IPS = {
}


start_time = datetime(2025, 11, 1, 0, 0, 0, 0)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


def get_uptime():
    """获取服务运行时间"""
    uptime = datetime.now() - start_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    if not parts:
        return "0 minute"
    return " ".join(parts)


def verify_api_key(provided_key):
    """验证 API 密钥"""
    if not provided_key:
        return False, "缺少 API 密钥"

    if provided_key in API_KEYS:
        return True, "API 密钥验证成功"
    else:
        return False, "无效的 API 密钥"


def get_client_ip():
    """
    按优先级从头部获取客户端真实IP
    如果所有头部都不存在，则返回本机地址
    """
    ip_headers = [
        'CF-Connecting-IP',
        'True-Client-IP',
        'X-Client-IP',
        'X-Real-IP',
        'X-Forwarded-For',
        'X-Cluster-Client-IP',
        'Forwarded-For',
        'Forwarded',
    ]

    for header in ip_headers:
        ip_value = request.headers.get(header)
        if ip_value:
            ips = [ip.strip() for ip in ip_value.split(',')]
            for ip in ips:
                if ip and ip.lower() != 'unknown':
                    return ip

    return request.remote_addr


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-API-Key')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')

    logger.info(f"{request.method} {request.path} - {response.status_code}")

    return response


@app.route('/')
def home():
    """首页，显示服务状态和文档"""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')

    logger.info(f"首页访问 - 客户端IP: {get_client_ip()}")

    return render_template(
        'index.html',
        start_time=start_time_str,
        current_time=current_time,
        uptime=get_uptime()
    )


@app.route('/favicon.ico')
def favicon():
    logger.info(f"favicon.ico访问 - 客户端IP: {get_client_ip()}")
    return '', 204


@app.route('/robots.txt')
def robots():
    logger.info(f"robots.txt访问 - 客户端IP: {get_client_ip()}")
    return send_from_directory(app.static_folder, 'robots.txt')


@app.route('/health', methods=['GET'])
def health():
    """健康检查接口"""
    logger.info(f"健康检查请求 - 客户端IP: {get_client_ip()}")

    return jsonify({
        "status": "healthy",
        "service": "BUAA Proxy",
        "timestamp": datetime.now().isoformat(),
        "uptime": get_uptime(),
        "version": "1.0.0"
    })


def get_pri_key():
    with open("private.key", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def rsa_decrypt(cipher_text):
    private_key = get_pri_key()
    cipher_bytes = base64.b64decode(cipher_text)
    raw_bytes = private_key.decrypt(cipher_bytes, padding.PKCS1v15())
    return raw_bytes.decode("utf-8")


def get_loginName_from_session(session, target_url, headers):
    """公共方法：请求跳转链接，提取loginName"""
    try:
        iclass_response = session.get(target_url, headers=headers, timeout=15)
        loginName_pattern = r'loginName=([^&]+)'
        loginName_match = re.search(loginName_pattern, iclass_response.url)
        if loginName_match:
            return loginName_match.group(1)
        return None
    except Exception as e:
        logger.error(f"请求iclass失败, 错误: {str(e)}")
        return None


def sso(username, password):
    """
    sso登录接口
    return: (成功标记: bool, 信息)
        True, loginName  -> 登录成功
        False, "pwd_wrong" -> 账号密码错误
        False, "risk_login_fail" -> 风控页面续登失败
        False, "no_execution" -> 拿不到execution
        False, "no_loginName" -> 跳转无loginName
        False, "code_xxx" -> HTTP异常状态码
        False, "except_xxx" -> 异常捕获
    """
    sso_login_url = "https://sso.buaa.edu.cn/login"
    verify_url    = "https://uc.buaa.edu.cn/"
    target_url    = "https://iclass.buaa.edu.cn:8346/?type=jumpMyCenter"

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9",
        'User-Agent': UA
    }

    session = requests.Session()

    try:
        logger.info(f"请求SSO登录页")
        sso_response = session.get(sso_login_url, headers=headers, timeout=15)

        if sso_response.status_code != 200:
            logger.error(f"SSO首页异常，状态码 - {sso_response.status_code}")
            return False, f"code_{sso_response.status_code}"

        logger.info(f"请求SSO登录页成功，状态码 - {sso_response.status_code}")
        if verify_url in sso_response.url:
            logger.info(f"会话有效，无需登录")
            loginName = get_loginName_from_session(session, target_url, headers)
            if loginName:
                logger.info(f"提取loginName成功")
                return True, loginName
            else:
                logger.error("提取loginName失败")
                return False, "no_loginName"

        execution_pattern = r'<input name="execution" value="([^"]+)"/>'
        execution_match = re.search(execution_pattern, sso_response.text)
        if not execution_match:
            logger.error(f"提取execution失败，execution字段不存在")
            return False, "no_execution"
        execution = execution_match.group(1)
        logger.info(f"提取execution成功")
        try:
            logger.info(f"尝试登录SSO")
            data = {
                'username' : username,
                'password' : password,
                'submit'   : '登录',
                'type'     : 'username_password',
                'execution': execution,
                '_eventId' : 'submit',
            }
            login_response = session.post(sso_login_url, headers=headers, data=data, allow_redirects=False, timeout=15)
            if login_response.status_code == 302:
                logger.info(f"登录SSO成功")
                loginName = get_loginName_from_session(session, target_url, headers)
                if loginName:
                    logger.info(f"提取loginName成功")
                    return True, loginName
                else:
                    logger.error("提取loginName失败")
                    return False, "no_loginName"
            elif login_response.status_code == 200:
                if "continueForm" in login_response.text:
                    logger.warning("触发账号安全风控，自动忽略风险续登")
                    risk_exec_match = re.search(execution_pattern, login_response.text)
                    if not risk_exec_match:
                        logger.error("风控页面无法提取execution")
                        return False, "risk_login_fail"
                    risk_exec = risk_exec_match.group(1)
                    risk_form = {
                        "execution": risk_exec,
                        "_eventId" : "ignoreAndContinue"
                    }
                    try:
                        risk_resp = session.post(sso_login_url, headers=headers, data=risk_form, allow_redirects=False, timeout=15)
                        if risk_resp.status_code == 302:
                            logger.info("风控绕过成功，登录完成")
                            loginName = get_loginName_from_session(session, target_url, headers)
                            if loginName:
                                logger.info(f"提取loginName成功")
                                return True, loginName
                            else:
                                logger.error("提取loginName失败")
                                return False, "no_loginName"
                        else:
                            logger.error("风控续登提交失败")
                            return False, "risk_login_fail"
                    except Exception as e:
                        logger.error(f"风控续登失败 - {str(e)}")
                        return False, "risk_login_fail"
                else:
                    logger.error("页面异常，登录失败")
                    return False, "code_200_unknown"
            elif login_response.status_code == 401:
                logger.error("登录失败：账号或密码错误")
                return False, "pwd_wrong"
            else:
                logger.error(f"登录SSO异常，状态码:{login_response.status_code}")
                return False, f"code_{login_response.status_code}"
        except Exception as e:
            logger.error(f"登录SSO失败 - {str(e)}")
            return False, f"except_{str(e)}"
    except Exception as e:
        logger.error(f"请求SSO登录页失败, 错误: {str(e)}")
        return False, f"except_{str(e)}"


@app.route('/api/iClassSchedule', methods=['GET'])
def login():
    """用户登录接口"""
    username = request.args.get('username')
    cipher_text = request.args.get('password')
    client_ip = get_client_ip()
    date_str = datetime.today().strftime('%Y%m%d')

    logger.info(f"课表查询 - 账号: {username}, 客户端IP: {client_ip}")

    if not username:
        logger.warning("登录请求缺少账号")
        return jsonify({"STATUS": "1", "message": "缺少账号（学号）"})

    if not cipher_text:
        logger.warning("登录请求缺少密码")
        return jsonify({"STATUS": "1", "message": "缺少密码"})

    if client_ip in BLACKLIST_IPS:
        logger.warning(f"受限制IP")
        return jsonify({"STATUS": "3", "message": "受限制IP，禁止访问"}), 403

    if username.strip().upper() not in WHITELIST_STUDENT_IDS:
        logger.warning(f"外部成员，禁止访问")
        return jsonify({"STATUS": "3", "message": "外部成员，禁止访问"}), 403

    password = rsa_decrypt(cipher_text)
    ok, res = sso(username, password)
    if ok:
        loginName = res
    else:
        if res == "pwd_wrong":
            return jsonify({"STATUS": "1", "message": "账号或密码错误"})
        elif res == "risk_login_fail":
            return jsonify({"STATUS": "1", "message": "账号存在安全风险，登录失败"})
        elif res == "no_loginName":
            return jsonify({"STATUS": "1", "message": "获取课程信息失败"})
        elif res.startswith("code"):
            return jsonify({"STATUS": "1", "message": f"SSO首页异常, {res}"})
        elif res == "code_200_unknown":
            return jsonify({"STATUS": "1", "message": f"SSO首页未知错误"})
        else:
            return jsonify({"STATUS": "1", "message": f"SSO登录失败"})

    try:
        login_url = 'https://iclass.buaa.edu.cn:8346/app/user/login.action'
        login_params = {
            'password': '',
            'phone': loginName,
            'userLevel': '1',
            'verificationType': '2',
            'verificationUrl': ''
        }
        login_headers = {
            'User-Agent': UA
        }

        logger.info(f"发送课程查询登录请求，学号: {username}")
        login_response = requests.get(login_url, params=login_params, headers=login_headers, verify=False, timeout=10)
        login_data = login_response.json()

        if login_data.get('STATUS') != '0':
            logger.warning(f"课程查询登录失败 - 学号: {username}, 状态: {login_data.get('STATUS')}")
            return jsonify(login_data)

        realName = login_data['result']['realName']
        logger.info(f"学号: {username}, 实际姓名: {realName}")

        user_id = login_data['result']['id']

    except Exception as e:
        logger.error(f"课程查询登录失败 - 学号: {username}, 错误: {str(e)}")
        return jsonify({"STATUS": "1", "message": f"课程查询登录失败: {str(e)}"})

    try:
        schedule_url = 'https://iclass.buaa.edu.cn:8346/app/course/get_stu_course_sched.action'

        schedule_params = {
            'dateStr': date_str,
            'id': user_id
        }
        schedule_headers = {
            'sessionId': loginName,
            'User-Agent': UA
        }

        schedule_response = requests.get(schedule_url, params=schedule_params, headers=schedule_headers, verify=False, timeout=10)
        schedule_data = schedule_response.json()
        schedule_data['user_id'] = user_id
        schedule_data['session_id'] = loginName

        course_count = len(schedule_data.get('result', []))
        logger.info(f"课表查询成功 - 学号: {username}, 课程数: {course_count}")

        if course_count == 0:
            return jsonify({"STATUS": "0", "message": f"查询日期没有课程"})
        return jsonify(schedule_data)

    except Exception as e:
        logger.error(f"课程查询失败 - 学号: {username}, 错误: {str(e)}")
        return jsonify({"STATUS": "1", "message": f"查询失败: {str(e)}"})


@app.route('/api/iClassSign', methods=['POST'])
def sign_in():
    """课程签到接口"""
    data = request.get_json()
    session_id = data.get('session_id')
    username = data.get('username')
    user_id = data.get('user_id')
    course_id = data.get('id')
    classBeginTime = data.get('classBeginTime')
    classEndTime = data.get('classEndTime')
    client_ip = get_client_ip()

    if not user_id or not course_id or not username or not classBeginTime or not classEndTime or not session_id:
        logger.warning("签到请求缺少参数")
        return jsonify({"STATUS": "1", "message": "缺少参数"})

    logger.info(f"签到请求 - 学号: {username}, 课程ID: {course_id}, 客户端IP: {client_ip}")

    if client_ip in BLACKLIST_IPS:
        logger.warning(f"受限制IP")
        return jsonify({"STATUS": "3", "message": "受限制IP，禁止访问"}), 403

    if username.strip().upper() not in WHITELIST_STUDENT_IDS:
        logger.warning(f"外部成员，禁止访问")
        return jsonify({"STATUS": "3", "message": "外部成员，禁止访问"}), 403

    now = datetime.now()
    begin_time = classBeginTime[11:16]
    end_time = classEndTime[11:16]
    # 解析开始时间和结束时间
    begin_time = datetime.strptime(begin_time, "%H:%M").replace(
        year=now.year, month=now.month, day=now.day
    )
    end_time = datetime.strptime(end_time, "%H:%M").replace(
        year=now.year, month=now.month, day=now.day
    )
    begin_time_minus_10 = begin_time - timedelta(minutes=10)

    if not begin_time_minus_10 <= now <= end_time:
        logger.warning("未到签到时间")
        return jsonify({"STATUS": "2", "message": "未到签到时间"})

    try:
        sign_url = 'http://iclass.buaa.edu.cn:8081/app/course/stu_scan_sign.action'
        timestamp_url = "http://iclass.buaa.edu.cn:8081/app/common/get_timestamp.action"

        timestamp_response = requests.get(timestamp_url, timeout=10)
        timestamp_result = timestamp_response.json()
        if not timestamp_result.get('STATUS') == '0':
            logger.error(f"获取服务器时间失败 - 错误: {timestamp_result.get('ERRMSG')}")
            logger.error(f"签到失败 - 学号: {username}, 课程ID: {course_id}, 错误: 获取服务器时间失败")
            return jsonify({"STATUS": "1", "message": "获取服务器时间失败"})
        elif timestamp_result.get('timestamp') == 'null' or timestamp_result.get('timestamp') == '':
            ts = int(time.time() * 1000)
        else:
            ts = timestamp_result.get('timestamp')

        sign_params = {
            'courseSchedId': course_id,
            'timestamp': ts,
            'id': user_id,
        }
        sign_headers = {
            'User-Agent': UA,
            'sessionId': session_id
        }
        sign_response = requests.post(sign_url, params=sign_params, headers=sign_headers, timeout=10)
        sign_result = sign_response.json()

        status = sign_result.get('STATUS')
        if status == '0':
            logger.info(f"签到成功 - 学号: {username}, 课程ID: {course_id}, 状态: {status}")
        else:
            logger.error(f"签到失败 - 学号: {username}, 课程ID: {course_id}, 错误: {sign_result.get('ERRMSG')}")

        return jsonify(sign_result)

    except Exception as e:
        logger.error(f"签到失败 - 学号: {username}, 课程ID: {course_id}, 错误: {str(e)}")
        return jsonify({"STATUS": "1", "message": f"签到失败: {str(e)}"})


@app.route('/proxy', methods=['POST'])
def proxy():
    """通用代理接口"""
    client_ip = get_client_ip()

    request_data = request.get_json()
    if not request_data:
        logger.warning(f"代理请求数据格式错误 - 客户端IP: {client_ip}")
        return jsonify({"error": "请求数据必须是JSON格式"}), 400

    apikey = request_data.get('API_KEY')
    is_valid, message = verify_api_key(apikey)
    if not is_valid:
        logger.warning(f"API密钥验证失败 - 客户端IP: {client_ip}, 原因: {message}")
        return jsonify({"error": message}), 403

    target_url = request_data.get('target_url')
    if not target_url:
        logger.warning(f"代理请求缺少URL参数 - 客户端IP: {client_ip}")
        return jsonify({"error": "缺少目标URL参数"}), 400

    method = request_data.get('target_method', 'GET').upper()
    headers = request_data.get('target_headers', {})
    params = request_data.get('target_params', {})
    data = request_data.get('target_data')
    json_data = request_data.get('target_json_data')

    safe_headers = {k: v for k, v in headers.items() if k.lower() not in ['authorization', 'cookie']}
    logger.info(f"代理请求 - 方法: {method}, URL: {target_url}, 客户端IP: {client_ip}, 头部: {safe_headers}")

    try:
        request_kwargs = {
            'method': method,
            'url': target_url,
            'headers': headers,
            'params': params,
            'timeout': 30,
            'verify': False
        }

        if data is not None:
            request_kwargs['data'] = data
        if json_data is not None:
            request_kwargs['json'] = json_data

        response = requests.request(**request_kwargs)

        result = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text,
            "url": response.url,
            "elapsed": str(response.elapsed),
            "timestamp": datetime.now().isoformat()
        }

        content_type = response.headers.get('Content-Type', '')
        if 'image' in content_type or 'octet-stream' in content_type:
            result["content"] = base64.b64encode(response.content).decode('utf-8')
            result["is_base64"] = True
        else:
            result["is_base64"] = False

        logger.info(f"代理请求成功 - 状态码: {response.status_code}, URL: {target_url}")
        return jsonify(result)

    except requests.exceptions.Timeout:
        logger.error(f"代理请求超时 - URL: {target_url}, 客户端IP: {client_ip}")
        return jsonify({"error": "请求超时"}), 504
    except requests.exceptions.ConnectionError:
        logger.error(f"代理连接错误 - URL: {target_url}, 客户端IP: {client_ip}")
        return jsonify({"error": "连接错误"}), 502
    except requests.exceptions.RequestException as e:
        logger.error(f"代理请求异常 - URL: {target_url}, 错误: {str(e)}, 客户端IP: {client_ip}")
        return jsonify({"error": f"请求异常: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"代理未知错误 - URL: {target_url}, 错误: {str(e)}, 客户端IP: {client_ip}")
        return jsonify({"error": f"未知错误: {str(e)}"}), 500


@app.errorhandler(404)
def not_found(error):
    """404 错误处理"""
    logger.warning(f"访问不存在的页面 - 路径: {request.path}, 客户端IP: {get_client_ip()}")
    return render_template('404.html', request_path=request.path), 404


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 BUAA 校园网代理服务启动")
    print(f"📁 模板目录: {os.path.join(os.path.dirname(__file__), 'templates')}")
    print(f"📝 日志文件: {os.path.abspath('buaa_proxy.log')}")
    print("🌐 服务地址: http://0.0.0.0:5000")
    print("🩺 健康检查: http://localhost:5000/health")
    print("=" * 60)

    logger.info("BUAA 代理服务启动")
    logger.info(f"服务运行在: http://0.0.0.0:5000")

    app.run(host='0.0.0.0', port=5000, debug=False)