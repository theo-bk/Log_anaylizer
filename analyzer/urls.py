from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('api/range/', views.get_range, name='get_range'),
    path('api/analyze/', views.analyze, name='analyze'),
    path('api/csv/', views.download_csv, name='download_csv'),
    # 대용량 파일: 서버 로컬 경로 직접 읽기
    path('api/range_path/', views.range_by_path, name='range_by_path'),
    path('api/analyze_path/', views.analyze_by_path, name='analyze_by_path'),
    path('api/trace/', views.trace_ip, name='trace_ip'),
]
