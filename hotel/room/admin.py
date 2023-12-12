# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin
# from .models import CustomUser

# class CustomUserAdmin(UserAdmin):
#     search_fields = ('username', 'email', 'phone')  # Add 'username' to the search fields

# admin.site.register(CustomUser, CustomUserAdmin)
from django.contrib import admin
from .models import CustomUser, Hostel, HostelRoom, HostelAllotmentRegistration
from django.db import models
from .models import Bill,MessPayment
from .models import DailyAttendance, AttendanceRecord


class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('registration_number', 'email', 'phone')

class HostelAdmin(admin.ModelAdmin):
    readonly_fields = ('get_total_allotments', 'get_remaining_capacity')

class HostelRoomAdmin(admin.ModelAdmin):
    list_display = ('hostel', 'floor_number', 'room_number', 'capacity', 'is_phd_only', 'get_vacancies')


    def get_remaining_capacity(self, obj):
        return obj.get_remaining_capacity()
    get_remaining_capacity.short_description = 'Remaining Capacity'

    def get_total_allotments(self, obj):
        return obj.get_total_allotments()
    get_total_allotments.short_description = 'Total Allotments'

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Hostel, HostelAdmin)
# admin.site.register(HostelRoom)
admin.site.register(HostelRoom, HostelRoomAdmin)
# admin.site.register(HostelAllotmentRegistration)

from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import HostelAllotmentRegistration
from .views import get_available_hostel_for_gender 
from django.utils import timezone
from django.contrib import messages
from .views import approve_allotment_request, reject_hostel_allotment

class GenderFilter(admin.SimpleListFilter):
    title = _('Gender')
    parameter_name = 'gender'

    def lookups(self, request, model_admin):
        return (
            ('all', _('All')),
            ('male', _('Male')),
            ('female', _('Female')),
            ('others', _('Others')),
        )

    def queryset(self, request, queryset):
        if self.value() == 'male':
            return queryset.filter(gender='male')
        elif self.value() == 'female':
            return queryset.filter(gender='female')
        elif self.value() == 'others':
            return queryset.filter(gender='others')
        else:
            return queryset

class HostelAllotmentRegistrationAdmin(admin.ModelAdmin):
    list_display = ('registration_number', 'full_name', 'department', 'get_gender_display', 'is_approved', 'is_rejected', 'allotted_hostel')  # Add 'get_gender_display' to the list_display
    search_fields = ('registration_number', 'full_name', 'department')  # Define the search fields here

    actions = ['approve_selected_hostel_allotments', 'reject_selected_hostel_allotments']  # Keep existing actions

    # list_filter = (GenderFilter,)

    def approve_selected_hostel_allotments(modeladmin, request, queryset):
        for registration in queryset:
            if not registration.is_approved:
                approve_allotment_request(request, registration.id)
                messages.success(request, f'Hostel allotment for {registration.full_name} is approved.')
            else:
                messages.warning(request, f'Hostel allotment for {registration.full_name} is already approved.')

    approve_selected_hostel_allotments.short_description = 'Approve selected hostel allotments'

    def reject_selected_hostel_allotments(modeladmin, request, queryset):
        for registration in queryset:
            if not registration.is_rejected:
                reject_hostel_allotment(request, registration.id)
                messages.success(request, f'Hostel allotment for {registration.full_name} is rejected.')
            else:
                messages.warning(request, f'Hostel allotment for {registration.full_name} is already rejected.')

    reject_selected_hostel_allotments.short_description = 'Reject selected hostel allotments'

    def save_model(self, request, obj, form, change):
        if obj.is_approved:
            gender = obj.gender
            hostel = get_available_hostel_for_gender(gender)
            if hostel:
                obj.allotted_hostel = hostel
                obj.allotted_date = timezone.now()
        super().save_model(request, obj, form, change)

    def get_gender_display(self, obj):
        return obj.gender.capitalize() if obj.gender else ''

    get_gender_display.short_description = 'Gender'

admin.site.register(HostelAllotmentRegistration, HostelAllotmentRegistrationAdmin)







admin.site.register(Bill)
admin.site.register(MessPayment)


from .models import Notification

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'notification_type', 'created_at')
    list_filter = ('notification_type', 'created_at')
    search_fields = ('title', 'content')
    date_hierarchy = 'created_at'


from django.contrib import admin
from .models import DailyAttendance, AttendanceRecord

from django import forms

# class AttendanceRecordForm(forms.ModelForm):
#     class Meta:
#         model = AttendanceRecord
#         fields = ['is_present']

# class AttendanceRecordInline(admin.TabularInline):
#     model = AttendanceRecord
#     form = AttendanceRecordForm  # Use the custom form for editing
#     extra = 0
#     readonly_fields = ('student_registration_number', 'student_full_name', 'attendance_date')
    
#     def student_registration_number(self, instance):
#         return instance.student.registration_number
#     student_registration_number.short_description = 'Registration Number'
    
#     def student_full_name(self, instance):
#         return instance.student.full_name if instance.student else ""
#     student_full_name.short_description = 'Full Name'
    
#     def attendance_date(self, instance):
#         return instance.attendance.date
#     attendance_date.short_description = 'Date'

    

# class DailyAttendanceAdmin(admin.ModelAdmin):
#     inlines = [AttendanceRecordInline]

# admin.site.register(DailyAttendance, DailyAttendanceAdmin)

from django import forms
from django.contrib import admin
from .models import DailyAttendance, AttendanceRecord

class AttendanceRecordForm(forms.ModelForm):
    class Meta:
        model = AttendanceRecord
        fields = ['is_present']

class AttendanceRecordInline(admin.TabularInline):
    model = AttendanceRecord
    form = AttendanceRecordForm
    extra = 0
    readonly_fields = ('student_registration_number', 'student_full_name', 'attendance_date', 'hostel_name', 'floor_number', 'room_number')

    def student_registration_number(self, instance):
        return instance.student.registration_number if instance.student else ""
    student_registration_number.short_description = 'Registration Number'

    def student_full_name(self, instance):
        return instance.student.full_name if instance.student else ""
    student_full_name.short_description = 'Full Name'

    def attendance_date(self, instance):
        return instance.attendance.date
    attendance_date.short_description = 'Date'

    def hostel_name(self, instance):
        return instance.student.allotted_hostel.name if instance.student.allotted_hostel else ""
    hostel_name.short_description = 'Hostel Name'

    def floor_number(self, instance):
        return instance.student.allotted_room.floor_number if instance.student.allotted_room else ""
    floor_number.short_description = 'Floor Number'

    def room_number(self, instance):
        return instance.student.allotted_room.room_number if instance.student.allotted_room else ""
    room_number.short_description = 'Room Number'

class DailyAttendanceAdmin(admin.ModelAdmin):
    list_display = ('date', 'hostel_details')

    def hostel_details(self, obj):
        return obj.hostel.name
    hostel_details.short_description = 'Hostel Details'

    inlines = [AttendanceRecordInline]

    search_fields = ['date', 'hostel__name', 'students__full_name', 'students__registration_number']


admin.site.register(DailyAttendance, DailyAttendanceAdmin)


# admin.py

from django.contrib import admin
from .models import ChangeRoomRequest
from .views import approved_change_room_request, reject_change_room_request

class ChangeRoomRequestAdmin(admin.ModelAdmin):
    list_display = ('registration_number', 'full_name', 'current_hostel', 'current_room_number', 'is_approved', 'is_rejected')
    # list_filter = ('is_approved', 'is_rejected')
    search_fields = ('registration_number', 'full_name', 'department')
    actions = ['bulk_change_room_approval', 'bulk_change_room_rejection']

    def bulk_change_room_approval(self, request, queryset):
        # Extract IDs and join them as a comma-separated string
        request_ids = ','.join(str(change_request.id) for change_request in queryset)
        return approved_change_room_request(request, request_ids)

    def bulk_change_room_rejection(self, request, queryset):
        # Extract IDs and join them as a comma-separated string
        request_ids = ','.join(str(change_request.id) for change_request in queryset)
        return reject_change_room_request(request, request_ids)


    bulk_change_room_approval.short_description = 'Bulk approve selected change room requests'
    bulk_change_room_rejection.short_description = 'Bulk reject selected change room requests'

admin.site.register(ChangeRoomRequest, ChangeRoomRequestAdmin)





from django.contrib import admin
from .models import CustomUser, ProfilePicture

class ProfilePictureInline(admin.StackedInline):
    model = ProfilePicture
    can_delete = False
    verbose_name_plural = 'Profile Pictures'

class CustomUserAdmin(admin.ModelAdmin):
    inlines = (ProfilePictureInline,)


from django.contrib import admin
from django import forms
from .models import MenuItem

class MenuItemAdminForm(forms.ModelForm):
    class Meta:
        model = MenuItem
        fields = '__all__'
        widgets = {
            'breakfast': forms.Textarea(attrs={'rows': 4}),  # Adjust 'rows' as needed
            'lunch': forms.Textarea(attrs={'rows': 4}),
            'tea': forms.Textarea(attrs={'rows': 4}),
            'dinner': forms.Textarea(attrs={'rows': 4}),
        }

@admin.register(MenuItem)
class MenuItemAdmin(admin.ModelAdmin):
    list_display = ('day', 'breakfast', 'lunch', 'tea', 'dinner')
    form = MenuItemAdminForm  # Use the custom form with Textarea widgets



from django.contrib import admin
from .models import FeedbackAndComplaint

@admin.register(FeedbackAndComplaint)
class FeedbackAndComplaintAdmin(admin.ModelAdmin):
    list_display = ('user_info', 'submission_date', 'rating', 'complaint_text')
    search_fields = ('user__registration_number', 'complaint_text')
    list_per_page = 20

    def user_info(self, obj):
        return f"{obj.user.registration_number} - {obj.user.get_full_name()}"

    # Add the action to delete selected items
    actions = ['delete_selected']

    def delete_selected(self, request, queryset):
        queryset.delete()

    delete_selected.short_description = "Delete selected items"

    # Customize the table column headers
    def changelist_view(self, request, extra_context=None):
        response = super().changelist_view(
            request, extra_context=extra_context,
        )
        if hasattr(response, 'context_data'):
            response.context_data['module_name'] = 'Feedback and Complaints'
            response.context_data['title'] = 'All Feedback and Complaints'
        return response

    def has_delete_permission(self, request, obj=None):
        return True  # Allow delete permission









# @admin.register(Attendance)
# class AttendanceAdmin(admin.ModelAdmin):
#     list_display = ('student', 'date', 'is_present')
#     list_filter = ('student', 'date', 'is_present')
#     search_fields = ('student__registration_number',)
    
#     # Define a custom admin action
#     actions = ['mark_present']

#     def mark_present(self, request, queryset):
#         # Update the selected attendance records to mark students as present
#         queryset.update(is_present=True)
#         self.message_user(request, f'Selected attendance records marked as present.')
#     mark_present.short_description = "Mark selected as present"


# from django.contrib import admin
# from room.models import CustomUser
# from django.contrib.auth.admin import UserAdmin

# # Register your models here.
# class CustomUserAdmin(UserAdmin):
#     list_display = ('email', 'registration_number', 'phone', 'is_active', 'is_admin')
#     # Add any other fields you want to display in the admin list

# admin.site.register(CustomUser)