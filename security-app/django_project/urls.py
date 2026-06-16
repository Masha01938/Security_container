from django.contrib import admin
from django.urls import path, include
from tasks import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('api/check/', views.check_request, name='check_request'),
    path('metrics/', include('django_prometheus.urls')),
]

# Принудительно добавляем метрики, если они не добавились
from django_prometheus import urls as prometheus_urls
if 'metrics' not in [p.pattern._route for p in urlpatterns]:
    urlpatterns.append(path('metrics/', include(prometheus_urls)))
