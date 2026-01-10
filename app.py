import os
import re
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# --- Конфигурация ---
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

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
}

SUSPICIOUS_SUBSTRINGS = [
    "..", "<", ">", "{", "}", "|", "^", "`", '"', "'", "\u200b", "\u200c", "\u200d"
]

SUSPICIOUS_WORDS = [
    "oplata", "login", "update", "payment", "pay", "bill", "account", "auth",
    "password", "credit", "card", "verify", "confirm", "bank", "wallet"
]

URL_PATTERNS = re.compile(r"https?://|ftp://", re.IGNORECASE)

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

        # 2) Проверка домена
        if not parsed.netloc:
            issues.append("Отсутствует домен")
            violations += 1
            return False, "; ".join(issues), violations

        # 3) Проверка белого списка доменов
        if not is_domain_allowed(parsed.netloc):
            issues.append(f"Домен {parsed.netloc} не в белом списке")
            violations += 1

        # 4) Проверка двойных слешей
        if "//" in parsed.path:
            issues.append("Обнаружены двойные слеши в пути")
            violations += 1

        # 5) Проверка подозрительных символов
        if any(s in url for s in SUSPICIOUS_SUBSTRINGS):
            issues.append("Обнаружены подозрительные символы")
            violations += 1

        # 6) Проверка вложенных URL
        if parsed.query:
            params = parse_qs(parsed.query)
            if contains_nested_url(params):
                issues.append("Обнаружены вложенные URL в параметрах")
                violations += 1

        if issues:
            return False, "; ".join(issues), violations
        return True, "URL безопасен", 0

    except Exception as e:
        return False, f"Ошибка парсинга URL: {e}", 1

def check_suspicious_words(url: str) -> tuple:
    """Проверка на подозрительные слова"""
    violations = 0
    issues = []
    
    try:
        # Проверка протокола
        if url.startswith("http://"):
            violations += 2
            issues.append("Используется небезопасный протокол HTTP (используйте HTTPS)")
        
        url_lower = url.lower()
        suspicious_found = [w for w in SUSPICIOUS_WORDS if w in url_lower]

        if suspicious_found:
            violations += len(suspicious_found)
            issues.append(f"Обнаружены подозрительные слова: {', '.join(suspicious_found)}")

        if issues:
            return False, "; ".join(issues), violations
        return True, "Подозрительные слова не найдены", 0

    except Exception as e:
        return False, f"Ошибка проверки: {e}", 1

def check_virustotal(url: str) -> tuple:
    """Проверка через VirusTotal API"""
    if not VT_API_KEY:
        return None, "VirusTotal API ключ не настроен", 0

    try:
        scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"

        # Отправка URL на сканирование
        params = {"apikey": VT_API_KEY, "url": url}
        response = requests.post(scan_url, data=params, timeout=15)
        
        if response.status_code != 200:
            return None, f"Ошибка VirusTotal API: {response.status_code}", 0

        scan_id = response.json().get("scan_id")
        if not scan_id:
            return None, "Не удалось получить ID сканирования", 0

        # Ожидание результатов
        time.sleep(10)

        # Получение отчета
        report_params = {"apikey": VT_API_KEY, "resource": url}
        report_response = requests.get(report_url, params=report_params, timeout=15)
        
        if report_response.status_code != 200:
            return None, f"Ошибка получения отчета: {report_response.status_code}", 0

        data = report_response.json()
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
    """Полная проверка веб-сайта"""
    results = []
    overall_status = "SAFE"
    overall_issues = []
    security_score = 100  # Начинаем с 100 баллов
    
    # Время начала проверки
    start_time = datetime.now()
    
    # 1) Проверка безопасности URL
    url_safe, url_issues, url_violations = is_url_safe(url)
    if not url_safe:
        security_score -= url_violations * 10
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
        security_score -= word_violations * 5
        overall_issues.append(f"Подозрительные слова: {word_issues}")
    
    results.append({
        "module": "suspicious_words",
        "safe": word_safe,
        "details": word_issues,
        "violations": word_violations,
        "icon": "🔍"
    })
    
    # 3) Проверка через VirusTotal
    vt_safe, vt_issues, vt_violations = check_virustotal(url)
    if vt_safe is False:
        security_score -= vt_violations * 15
        overall_issues.append(f"VirusTotal: {vt_issues}")
        overall_status = "DANGEROUS"
    elif vt_safe is None:
        security_score -= 5
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
    if security_score >= 80:
        overall_status = "SAFE"
        status_color = "success"
    elif security_score >= 50:
        overall_status = "WARNING"
        status_color = "warning"
    else:
        overall_status = "DANGEROUS"
        status_color = "danger"
    
    # Время окончания проверки
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    return {
        "url": url,
        "status": overall_status,
        "status_color": status_color,
        "security_score": max(0, min(100, security_score)),
        "issues": overall_issues,
        "modules": results,
        "checked_at": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{duration:.2f} сек"
    }

# --- Маршруты Flask ---

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
