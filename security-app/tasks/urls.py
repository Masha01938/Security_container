from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('api/check/', views.check_request, name='check_request'),
]
