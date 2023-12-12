from django.contrib import admin
from django.urls import path,include
from room import views
from .views import *

urlpatterns = [
    path("", views.SignupPage, name='register'),
    path("login/",views.LoginPage,name='login'),
    path('logout/',views.LogoutPage,name='logout'),
]

