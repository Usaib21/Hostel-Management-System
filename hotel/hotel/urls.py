"""
URL configuration for hotel project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from room import views
from room.views import UserProfileView,generate_pdf
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
# from room.views import ForgetPassword,ChangePassword
from room.views import available_rooms_for_change,save_profile_picture,get_profile_picture,get_students,before_change_room,noc_form,mess_committee


admin.site.site_header = "HOSTEL Admin"
admin.site.site_title = "HOSTEL Administration Portal"
admin.site.index_title = "Welcome To HOSTEL ADMINISTRATION PANEL"


urlpatterns = [
    path('admin/', admin.site.urls),
    path('signup/',views.SignupPage,name='signup'),
    path('',views.LoginPage,name='login'),
    path('home/',views.HomePage,name='home'),
    path('logout/',views.LogoutPage,name='logout'),
    path('menu/', views.menu_page, name='menu_page'),
    path('edit-menu/', views.edit_menu, name='edit_menu'),
    path('feedback_complaint/', views.feedback_complaint_view, name='feedback_complaint'),
    path('feedback_complaint/', views.feedback_complaint_view, name='submit_feedback_complaint'),
 # Password reset links (ref: https://github.com/django/django/blob/master/django/contrib/auth/views.py)
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='password_reset/password_change_done.html'), 
        name='password_change_done'),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='password_reset/password_change.html'), 
        name='password_change'),

    path('password_reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset/password_reset_done.html'),
     name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset/password_reset_complete.html'),
     name='password_reset_complete'),

    path('email_settings/', views.email_settings, name='email_settings'),
    path('user_profile/', UserProfileView.as_view(), name='user_profile'),
    path('save_profile_picture/', save_profile_picture, name='save_profile_picture'),
    path('get_profile_picture/', get_profile_picture, name='get_profile_picture'),

    # path('forget-password/' , ForgetPassword , name="forget_password"),
    # path('change-password/<token>/' , ChangePassword , name="change_password"),

    path('hostel_allotment_registration/', views.hostel_allotment_registration, name='hostel_allotment_registration'),
    path('admin/approve-allotment/<int:registration_id>/', views.approve_allotment_request, name='approve_allotment_request'),
    path('reject_hostel_allotment/<int:registration_id>/', views.reject_hostel_allotment, name='reject_hostel_allotment'),
    path('registration_success/<int:pk>/', views.registration_success, name='registration_success'),
    # path('registration_success/<int:allotment_id>/', views.display_available_rooms, name='registration_success'),
    path('room_details/<int:room_id>/', views.room_details, name='room_details'),
    path('terms_and_conditions/', views.terms_and_conditions, name='terms_and_conditions_page'),



    path('display_available_rooms/<int:allotment_id>/', views.display_available_rooms, name='display_available_rooms'),
    path('room_details/<int:room_id>/', views.room_details, name='room_details'),
    path('change_room/', views.change_room, name='change_room'),
    path('display_available_rooms/', views.display_available_rooms, name='display_available_rooms'),
    path('allot_room/<int:room_id>/', views.allot_room, name='allot_room'),
    path('available_rooms/', views.available_rooms, name='available_rooms'),
    path('available_floors/<int:hostel_id>/', views.available_floors, name='available_floors'),
    path('available_rooms/<int:hostel_id>/<int:floor_number>/', views.available_rooms_on_floor, name='available_rooms_on_floor'),
    path('get_available_floors/<int:hostel_id>/', views.get_available_floors, name='get_available_floors'),
    path('already_allotted/<int:allotment_id>/', views.already_allotted, name='already_allotted'),
    path('hostel/<int:hostel_id>/floor/<int:floor_number>/change/', available_rooms_for_change, name='available_rooms_for_change'),
    path('available_floors_for_change/<int:hostel_id>/', views.available_floors_for_change, name='available_floors_for_change'),
    path('available_rooms_for_change/<int:hostel_id>/<int:floor_number>/', views.available_rooms_for_change, name='available_rooms_for_change'),
    path('before_change_room/', before_change_room, name='before_change_room'),
    path('change-room/approve/<int:request_id>/', views.approved_change_room_request, name='approve_change_room_request'),
    path('change-room/reject/<int:request_id>/', views.reject_change_room_request, name='reject_change_room_request'),
    path('cancel_hostel/', views.cancel_hostel, name='cancel_hostel'),
    path('hostel_details/', views.hostel_details, name='hostel_details'),

    path('hostel/payments/', views.hostel_payments, name='hostel_payments'),
    path('mess/payments/', views.mess_payments, name='mess_payments'),
    path('bill/<int:pk>/', views.bill_detail, name='bill_detail'),
    path('mess-bill-details/<int:mess_payment_id>/', views.mess_bill_details, name='mess_bill_details'),
    path('download_mess_bill/<int:mess_payment_id>/', views.download_mess_bill, name='download_mess_bill'),
    path('notifications/', views.view_notifications, name='notifications'),
    path('notifications/<int:notification_id>/', views.notification_detail, name='notification_detail'),
    path('generate_pdf/<int:bill_id>/', generate_pdf, name='generate_pdf'),
    path('take_attendance/', views.take_attendance, name='take_attendance'),
    path('upload_attendance/', views.upload_attendance, name='upload_attendance'),
    path('edit_attendance/', views.edit_attendance, name='edit_attendance'),
    path('view_attendance/', views.view_attendance, name='view_attendance'),
    path('get_students/', get_students, name='get_students'),
    path('save_attendance/', views.save_attendance, name='save_attendance'),
   # Add a new URL pattern for fetching available hostels
   path('get_available_hostels/', views.get_available_hostels, name='get_available_hostels'),
   path('get_available_floors_for_attendance/<int:hostel_id>/', views.get_available_floors_for_attendance, name='get_available_floors_for_attendance'),
   path('available_students_on_floor/<int:hostel_id>/<int:floor_number>/', views.available_students_on_floor, name='available_students_on_floor'),
   path('noc_form/', noc_form, name='noc_form'),
   path('mess_committee/', mess_committee, name='mess_committee'),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
