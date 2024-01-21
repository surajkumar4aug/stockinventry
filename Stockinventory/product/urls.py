from django.urls import path
from .views import ProductAPIView

urlpatterns = [
    path('products/', ProductAPIView.as_view()),
    path('products/<str:pk>/', ProductAPIView.as_view()),
]
