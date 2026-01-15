import os
import re
import time
import json
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv
from http.cookies import SimpleCookie
import hashlib

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# --- Конфигурация ---
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
API_KEY = os.environ.get("API_KEY", "0a8792786b28888d5ed738d039b83202d77509c440fa02524ecfca961353b07d").strip()

WHITELISTED_DOMAINS = {
    "example.com",
    "trusted-site.org",
    "safe-site.com",
    "python.org",
    "sdamgia.ru",
    "www.virustotal.com",
    "github.com",
    "stackoverflow.com",
    "google.com",
    "ptsecurity.com",
    "https://lacmus.onrender.com/",
}

SUSPICIOUS_SUBSTRINGS = [
    "..", "<", ">", "{", "}", "|", "^", "`", '"', "'", "\u200b", "\u200c", "\u200d",
    "\\"  # Добавлен обратный слеш из кода 1
]

SUSPICIOUS_WORDS = [
    "oplata", "login", "update", "payment", "pay", "bill", "account", "auth",
    "password", "credit", "card", "verify", "confirm", "bank", "wallet"
]

URL_PATTERNS = re.compile(r"https?://|ftp://", re.IGNORECASE)
ALLOWED_PATTERN = re.compile(r'^[a-zA-Z0-9\-._~:/?=&%+#@!]*$')

def is_domain_allowed(domain: str) -> bool:
    """Проверка домена на разрешение"""
    d = domain.lower()
    for allowed in WHITELISTED_DOMAINS:
        if d == allowed or d.endswith("." + allowed):
            return True
    return False

def contains_nested_url(params: dict) -> bool:
    """Проверка на вложенные URL в параметрах"""
    for values in params.values():
        for v in values:
            decoded = unquote(v)
            if URL_PATTERNS.search(decoded):
                return True
    return False

def is_url_safe(url: str) -> tuple:
    """Проверка безопасности URL"""
    issues = []
    violations = 0
    
    try:
        parsed = urlparse(url)

        # 1) Проверка протокола
        if not parsed.scheme:
            issues.append("Отсутствует протокол (http/https)")
            violations += 1
            return False, "; ".join(issues), violations
        
        # HTTP считается небезопасным
        if url.startswith('http://'):
            issues.append("Используется небезопасный протокол HTTP")
            violations += 2

        # 2) Проверка домена
        if not parsed.netloc:
            issues.append("Отсутствует домен")
            violations += 1
            return False, "; ".join(issues), violations

        # 3) Проверка белого списка доменов
        if not is_domain_allowed(parsed.netloc):
            issues.append(f"Домен {parsed.netloc} не в белом списке")
            violations += 0.2

        # 4) Проверка двойных слешей
        scheme_part = parsed.scheme + "://"
        after_scheme = url[len(scheme_part):]
        if '//' in after_scheme:
            issues.append("Обнаружены двойные слеши в пути")
            violations += 1

        # 5) Проверка разрешенных паттернов
        if not ALLOWED_PATTERN.match(url):
            issues.append("URL содержит недопустимые символы")
            violations += 2

        # 6) Проверка подозрительных символов
        suspicious_found = [s for s in SUSPICIOUS_SUBSTRINGS if s in url]
        if suspicious_found:
            issues.append(f"Обнаружены подозрительные символы: {', '.join(suspicious_found)}")
            violations += 2 * len(suspicious_found)

        # 7) Проверка вложенных URL
        if parsed.query:
            params = parse_qs(parsed.query)
            if contains_nested_url(params):
                issues.append("Обнаружены вложенные URL в параметрах")
                violations += 2

        if issues:
            return False, "; ".join(issues), violations
        return True, "URL безопасен", 0

    except Exception as e:
        return False, f"Ошибка парсинга URL: {e}", 1

def check_suspicious_words(url: str) -> tuple:
    """Проверка на подозрительные слова (улучшена из кода 1)"""
    violations = 0
    issues = []
    
    try:
        # Проверка подозрительных слов
        url_lower = url.lower()
        suspicious_found = []
        
        # Проверка на SUSPICIOUS_WORDS
        for word in SUSPICIOUS_WORDS:
            if word in url_lower:
                suspicious_found.append(word)
                violations += 1
        
        if suspicious_found:
            issues.append(f"Обнаружены подозрительные слова: {', '.join(suspicious_found)}")

        if issues:
            return False, "; ".join(issues), violations
        return True, "Подозрительные слова не найдены", 0

    except Exception as e:
        return False, f"Ошибка проверки: {e}", 1

def check_cookies_security(url: str) -> tuple:
    """Проверка безопасности cookies (из кода 1, адаптировано)"""
    violations = 0
    issues = []
    detailed_report = []
    
    try:
        # Устанавливаем безопасные заголовки для запроса
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=True, allow_redirects=True)
        cookies = response.cookies
        security_headers = response.headers
        
        if not cookies:
            return True, "Cookies не обнаружены", 0
        
        detailed_report.append(f"Найдено cookies: {len(cookies)}")
        
        for cookie in cookies:
            cookie_violations = 0
            cookie_issues = []
            
            # Проверка Secure флага
            if not cookie.secure:
                cookie_violations += 1
                cookie_issues.append("Отсутствует Secure флаг")
            
            # Проверка HttpOnly флага
            if not cookie.has_nonstandard_attr('httponly'):
                # Альтернативная проверка для различных библиотек
                if 'HttpOnly' not in str(cookie):
                    cookie_violations += 1
                    cookie_issues.append("Отсутствует HttpOnly флаг")
            
            # Проверка SameSite атрибута
            samesite = getattr(cookie, '_rest', {}).get('SameSite', None)
            if not samesite:
                samesite = getattr(cookie, 'samesite', None)
            
            if not samesite or samesite == "Не задано":
                cookie_violations += 1
                cookie_issues.append("Отсутствует или некорректный SameSite атрибут")
            
            # Проверка срока действия
            expires = cookie.expires
            if not expires:
                cookie_violations += 0.5  # Меньший вес, так как не всегда критично
                cookie_issues.append("Не задан срок действия")
            
            # Добавляем информацию о cookie
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr('httponly') or 'HttpOnly' in str(cookie),
                "samesite": samesite,
                "expires": expires,
                "violations": cookie_violations,
                "issues": cookie_issues
            }
            
            detailed_report.append(cookie_info)
            violations += cookie_violations
        
        # Анализ заголовков безопасности (из кода 1)
        security_headers_report = []
        
        # CSP заголовок
        csp = security_headers.get('Content-Security-Policy', None)
        if not csp:
            violations += 1
            security_headers_report.append("Отсутствует Content-Security-Policy")
        
        # X-Frame-Options
        xfo = security_headers.get('X-Frame-Options', None)
        if not xfo:
            violations += 1
            security_headers_report.append("Отсутствует X-Frame-Options")
        
        # HSTS
        hsts = security_headers.get('Strict-Transport-Security', None)
        if not hsts:
            violations += 0.5  # Меньший вес
            security_headers_report.append("Отсутствует Strict-Transport-Security")
        
        if security_headers_report:
            issues.extend(security_headers_report)
        
        summary = f"Найдено {len(cookies)} cookies, нарушений: {int(violations)}"
        if detailed_report:
            summary += f" | Подробности: {json.dumps(detailed_report, ensure_ascii=False)}"
        
        if violations > 0:
            return False, summary, violations
        return True, summary, 0
        
    except requests.exceptions.SSLError:
        return False, "Ошибка SSL сертификата", 1
    except requests.exceptions.Timeout:
        return False, "Таймаут при проверке cookies", 1
    except requests.exceptions.ConnectionError:
        return False, "Ошибка подключения", 1
    except Exception as e:
        return False, f"Ошибка при проверке cookies: {str(e)}", 1

def check_virustotal(url: str) -> tuple:
    """Проверка через VirusTotal API (из кода 2, с улучшениями из кода 1)"""
    if not VT_API_KEY:
        return None, "VirusTotal API ключ не настроен", 0

    try:
        # Используем URL для проверки вместо scan (как в коде 1 и 2)
        report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        
        # Параметры как в коде 1
        report_params = {
            'apikey': VT_API_KEY, 
            'resource': url,
            'scan': 1  # Запрашиваем сканирование, если URL не в базе
        }
        
        # Получение отчета (объединенный подход)
        response = requests.get(report_url, params=report_params, timeout=15)
        
        if response.status_code != 200:
            # Если URL нет в базе, пытаемся отправить на сканирование (как в коде 1)
            if response.status_code == 204:  # No content
                scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
                scan_params = {"apikey": VT_API_KEY, "url": url}
                scan_response = requests.post(scan_url, data=scan_params, timeout=15)
                
                if scan_response.status_code == 200:
                    scan_data = scan_response.json()
                    scan_id = scan_data.get("scan_id")
                    
                    # Ждем результат сканирования (как в коде 1)
                    time.sleep(5)
                    
                    # Запрашиваем отчет по scan_id
                    report_params = {'apikey': VT_API_KEY, 'resource': scan_id}
                    report_response = requests.get(report_url, params=report_params, timeout=15)
                    
                    if report_response.status_code == 200:
                        data = report_response.json()
                    else:
                        return None, f"Ошибка получения отчета после сканирования: {report_response.status_code}", 0
                else:
                    return None, f"Ошибка отправки на сканирование: {scan_response.status_code}", 0
            else:
                return None, f"Ошибка VirusTotal API: {response.status_code}", 0
        else:
            data = response.json()
        
        # Обработка результатов (как в коде 2)
        positives = int(data.get("positives", 0) or 0)
        total = int(data.get("total", 0) or 0)
        
        if total <= 0:
            return None, "Нет данных для анализа", 0

        detection_rate = (positives / total) * 100.0
        
        if positives == 0:
            return True, f"Безопасен (0/{total} детекторов)", 0
        elif detection_rate < 10:
            return False, f"Подозрительный ({positives}/{total} детекторов)", positives
        else:
            return False, f"Опасен ({positives}/{total} детекторов)", positives * 2

    except requests.exceptions.Timeout:
        return None, "Таймаут запроса к VirusTotal", 0
    except Exception as e:
        return None, f"Ошибка: {str(e)}", 0

def comprehensive_website_check(url: str) -> dict:
    """Полная проверка веб-сайта с добавленными проверками из кода 1"""
    results = []
    overall_status = "SAFE"
    overall_issues = []
    security_score = 0  # Начинаем с 0 баллов
    
    # Время начала проверки
    start_time = datetime.now()
    
    # 1) Проверка безопасности URL (объединенная)
    url_safe, url_issues, url_violations = is_url_safe(url)
    if not url_safe:
        security_score += url_violations * 10
        overall_issues.append(f"Проблемы с URL: {url_issues}")
    
    results.append({
        "module": "url_safety",
        "safe": url_safe,
        "details": url_issues,
        "violations": url_violations,
        "icon": "🔗"
    })
    
    # 2) Проверка подозрительных слов
    word_safe, word_issues, word_violations = check_suspicious_words(url)
    if not word_safe:
        security_score += word_violations * 10
        overall_issues.append(f"Подозрительные слова: {word_issues}")
    
    results.append({
        "module": "suspicious_words",
        "safe": word_safe,
        "details": word_issues,
        "violations": word_violations,
        "icon": "🔍"
    })
    
    # 3) Проверка cookies безопасности
    try:
        cookies_safe, cookies_issues, cookies_violations = check_cookies_security(url)
        if not cookies_safe:
            security_score += cookies_violations * 5  # Средний вес
            overall_issues.append(f"Проблемы с cookies: {cookies_issues.split(' | ')[0]}")
        
        results.append({
            "module": "cookies_security",
            "safe": cookies_safe,
            "details": cookies_issues,
            "violations": cookies_violations,
            "icon": "🍪"
        })
    except Exception as e:

        security_score += 10
        results.append({
            "module": "cookies_security",
            "safe": None,
            "details": f"Ошибка проверки cookies: {str(e)}",
            "violations": 0,
            "icon": "🍪"
        })
    
    # 4) Проверка через VirusTotal
    vt_safe, vt_issues, vt_violations = check_virustotal(url)
    if vt_safe is False:
        security_score += vt_violations * 50  # Высокий вес для VirusTotal
        overall_issues.append(f"VirusTotal: {vt_issues}")
        overall_status = "DANGEROUS"
    elif vt_safe is None:
        security_score += 10
        overall_issues.append(f"VirusTotal недоступен: {vt_issues}")
        if overall_status != "DANGEROUS":
            overall_status = "WARNING"
    
    results.append({
        "module": "virustotal",
        "safe": vt_safe,
        "details": vt_issues,
        "violations": vt_violations,
        "icon": "🛡️"
    })
    
    # Определение общего статуса на основе score
    if security_score <= 19:
        overall_status = "SAFE"
        status_color = "success"
    elif security_score <= 49:
        overall_status = "WARNING"
        status_color = "warning"
    elif security_score <= 79:
        overall_status <= "DANGEROUS"
        status_color = "danger"
    else:
        overall_status = "VERY_DANGEROUS"
        status_color = "danger"
    
    # Время окончания проверки
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Формирование итогового отчета
    report_data = {
        "url": url,
        "status": overall_status,
        "status_color": status_color,
        "security_score": max(0, min(1000, security_score)),
        "issues": overall_issues,
        "modules": results,
        "checked_at": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{duration:.2f} сек"
    }
    
    # Добавляем подробную информацию о cookies если есть
    for module in results:
        if module["module"] == "cookies_security" and "Подробности" in module["details"]:
            try:
                # Извлекаем JSON из строки
                details_str = module["details"]
                if "Подробности: " in details_str:
                    json_str = details_str.split("Подробности: ")[1]
                    cookies_details = json.loads(json_str)
                    report_data["cookies_details"] = cookies_details
            except:
                pass  # Если не удалось распарсить, пропускаем
    
    return report_data


@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/check', methods=['GET', 'POST'])
def check():
    """Обработка проверки URL"""
    if request.method == 'POST':
        # Получаем данные из JSON запроса (а не из формы)
        if request.is_json:
            data = request.get_json()
            url = data.get('url', '').strip() if data else ''
        else:
            url = request.form.get('url', '').strip()
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        try:
            # Добавляем протокол если его нет
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Проверяем URL
            result = comprehensive_website_check(url)
            
            # Конвертируем статус в формат, ожидаемый фронтендом
            status_mapping = {
                "SAFE": "ok",
                "WARNING": "unknown",
                "DANGEROUS": "blocked"
            }
            
            # Формируем ответ в формате, ожидаемом фронтендом
            response = {
                "status": status_mapping.get(result.get("status", "unknown"), "unknown"),
                "report": result  # Отправляем полный отчет
            }
            
            return jsonify(response)
            
        except Exception as e:
            return jsonify({"error": str(e), "status": "unknown"}), 500
    
    # Для GET запросов - редирект на главную
    return redirect(url_for('index'))

@app.route('/api/check')
def api_check():
    """API endpoint для проверки URL"""
    url = request.args.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    
    try:
        result = comprehensive_website_check(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint для Render"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/about')
def about():
    """Страница о проекте"""
    return render_template('about.html')

# Обработчик ошибок
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Для запуска локально
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)