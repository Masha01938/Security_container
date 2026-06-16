from django.shortcuts import render
from django.http import JsonResponse
import json
from prometheus_client import Counter

# Списки доверенных и вредоносных ресурсов
TRUSTED_SITES = [
    'trusted-bank.ru',
    'safe-site.com',
    'trusted-service.com',
]

MALICIOUS_SITES = [
    'malware-site.com',
    'malicious-site.ru',
    'hack-site.org',
    'phishing-site.com',
]

DANGEROUS_CONTENT = ['exe', 'script', 'bin', 'msi']

# Бизнес-метрики для Prometheus
allowed_counter = Counter('security_allowed_total', 'Total number of allowed requests')
blocked_counter = Counter('security_blocked_total', 'Total number of blocked requests')
quarantine_counter = Counter('security_quarantine_total', 'Total number of quarantine requests')


def analyze_request(url, content_type):
    """Анализирует запрос и возвращает решение и причину"""
    for site in MALICIOUS_SITES:
        if site in url:
            return 'blocked', f'Сайт {site} в списке вредоносных'

    for site in TRUSTED_SITES:
        if site in url:
            if content_type in DANGEROUS_CONTENT:
                return 'blocked', f'Доверенный ресурс, но обнаружен опасный тип контента ({content_type})'
            return 'allowed', f'Доверенный ресурс ({site}), контент безопасен'

    if content_type in DANGEROUS_CONTENT:
        return 'blocked', f'Обнаружен опасный тип контента ({content_type}) на неизвестном ресурсе'

    return 'quarantine', 'Неизвестный ресурс, контент безопасен'


def index(request):
    return render(request, "index.html", {})


def security_dashboard(request):
    """Главная панель мониторинга (статистика и таблица запросов)"""
    # Статистика решений контейнера безопасности
    stats = {
        'allowed': 15,
        'blocked': 8,
        'quarantine': 5,
    }

    # Список последних запросов для отображения в таблице
    recent_requests = [
        {'user': 'ivanov', 'url': 'https://safe-site.com', 'content': 'html', 'decision': 'allowed', 'reason': 'Безопасный ресурс'},
        {'user': 'attacker', 'url': 'https://malware-site.com', 'content': 'exe', 'decision': 'blocked', 'reason': 'Сайт в списке вредоносных'},
        {'user': 'petrov', 'url': 'https://unknown-site.net', 'content': 'html', 'decision': 'quarantine', 'reason': 'Неизвестный ресурс'},
        {'user': 'sidorov', 'url': 'https://safe-site.com', 'content': 'exe', 'decision': 'blocked', 'reason': 'Обнаружен опасный тип контента'},
        {'user': 'ivanov', 'url': 'https://unknown-site.net', 'content': 'script', 'decision': 'blocked', 'reason': 'Обнаружен опасный тип контента'},
        {'user': 'petrov', 'url': 'https://safe-site.com', 'content': 'image', 'decision': 'allowed', 'reason': 'Безопасный ресурс'},
        {'user': 'attacker', 'url': 'https://phishing-site.com', 'content': 'html', 'decision': 'blocked', 'reason': 'Сайт в списке вредоносных'},
    ]

    context = {
        'stats': stats,
        'recent_requests': recent_requests,
    }

    # Обновляем счётчики Prometheus
    allowed_counter.inc(stats.get('allowed', 0))
    blocked_counter.inc(stats.get('blocked', 0))
    quarantine_counter.inc(stats.get('quarantine', 0))

    return render(request, 'security_dashboard.html', context)


def check_request(request):
    """API для проверки отдельного запроса (AJAX) — только результат, без сохранения"""
    if request.method == 'POST':
        data = json.loads(request.body)
        url = data.get('url', '')
        content_type = data.get('content_type', '')

        decision, reason = analyze_request(url, content_type)

        color = {
            'allowed': 'green',
            'blocked': 'red',
            'quarantine': 'orange'
        }.get(decision, 'black')

        return JsonResponse({
            'decision': decision,
            'reason': reason,
            'color': color,
            'decision_ru': {
                'allowed': '✅ Allowed (разрешено)',
                'blocked': '⛔ Blocked (заблокировано)',
                'quarantine': '⚠️ Quarantine (карантин)'
            }.get(decision, decision)
        })

    return JsonResponse({'error': 'Метод не поддерживается'}, status=405)
