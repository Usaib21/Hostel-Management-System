# forms.py

from django import forms
from .models import HostelAllotmentRegistration,Notification
import calendar


class EmailSettingsForm(forms.Form):
    email_host = forms.CharField(label='Email Host', max_length=100)
    email_port = forms.IntegerField(label='Email Port')
    email_username = forms.EmailField(label='Email Username')
    email_password = forms.CharField(label='Email Password', widget=forms.PasswordInput)
    default_from_email = forms.EmailField(label='Default From Email')


class HostelAllotmentRegistrationForm(forms.ModelForm):
    GENDER_CHOICES = (
        ('', 'None'),  # None as the default choice
        ('male', 'Male'),
        ('female', 'Female'),
    
    )

    SEMESTER_CHOICES = (
        ('', 'None'),  # None as the default choice
        ('semester1', 'Semester 1'),
        ('semester2', 'Semester 2'),
        ('semester3', 'Semester 3'),
        ('semester4', 'Semester 4'),
        ('semester5', 'Semester 5'),
        ('semester6', 'Semester 6'),
        ('semester7', 'Semester 7'),
        ('semester8', 'Semester 8'),
    )
    DEPARTMENT_CHOICES = (
    ('', 'None'),  # None as the default choice
    ('Department of Management Studies', 'Department of Management Studies'),
    ('Department of Economics', 'Department of Economics'),
    ('Alamdar Memorial College of Nursing & Medical Technology, Charar-e-Sharief', 'Alamdar Memorial College of Nursing & Medical Technology, Charar-e-Sharief'),
    ('Syed Mantaqi Memorial College of Nursing & Medical Technology, Awantipora ','Syed Mantaqi Memorial College of Nursing & Medical Technology, Awantipora '),
    ('Centre For Vocational Studies','Centre For Vocational Studies'),
    ('Watson-Crick Centre for Molecular Medicine','Watson-Crick Centre for Molecular Medicine'),
    ('Centre for International Relations','Centre for International Relations'),
    (' Department of Arabic Language & Literature',' Department of Arabic Language & Literature'),
    ('Department of English Language & Literature','Department of English Language & Literature'),
    ('Department of Islamic Studies','Department of Islamic Studies'),
    ('Department of Journalism & Mass Communication','Department of Journalism & Mass Communication'),
    ('Averroes Centre for Philosophical Studies','Averroes Centre for Philosophical Studies'),
    ('Habba Khatoon Centre for Kashmiri Language & Literature','Habba Khatoon Centre for Kashmiri Language & Literature'),
    ('Ibn Khuldun Centre for Comparative Civilizations','Ibn Khuldun Centre for Comparative Civilizations'),
    ('International Centre for Spiritual Studies','International Centre for Spiritual Studies'),
    ('Rinchen Shah Centre for West Himalayan Cultures','Rinchen Shah Centre for West Himalayan Cultures'),
    ('Department of Chemistry','Department of Chemistry'),
    (' Department of Mathematical Sciences',' Department of Mathematical Sciences'),
    ('Department of Physics ','Department of Physics '),
    (' Mantaqi Centre for Science & Society',' Mantaqi Centre for Science & Society'),
    ('Department of Civil Engineering','Department of Civil Engineering'),
    ('Department of Computer Science & Engineering','Department of Computer Science & Engineering'),
    ('Department of Computer Science','Department of Computer Science'),
    ('Department of Electrical Engineering','Department of Electrical Engineering'),
    ('Department of Electronics Communication & Engineering','Department of Electronics Communication & Engineering'),
    ('Department of Food Technology','Department of Food Technology'),
    ('Department of Food Technology','Department of Food Technology'),
    (' Polytechnic College',' Polytechnic College'),
    ('Centre for Innovation & Entrepreneurship Development','Centre for Innovation & Entrepreneurship Development'),
    ('Centre for Innovation & Entrepreneurship Development','Centre for Innovation & Entrepreneurship Development'),
    ('Admission to B.Tech. / Diploma (Lateral Entry)','Admission to B.Tech. / Diploma (Lateral Entry)'),
    ('Department of Architecture','Department of Architecture'),

    # Add more departments here
)
    
    
    full_name = forms.CharField(max_length=100, label="Full Name")
    father_name = forms.CharField(max_length=200, label="Father's Name")
    religion = forms.CharField(max_length=50)
    district = forms.CharField(max_length=50)
    state = forms.CharField(max_length=50)
    country = forms.CharField(max_length=50)
    gender = forms.ChoiceField(choices=GENDER_CHOICES)
    semester = forms.ChoiceField(choices=SEMESTER_CHOICES)
    department = forms.ChoiceField(choices=DEPARTMENT_CHOICES, required=False)
    


  

    class Meta:
        model = HostelAllotmentRegistration
        fields = [
            'full_name',
            'father_name',
            'registration_number',
            'email',
            'phone',
            'department',
            'course',
            'semester',
            'gender',
            'religion',
            'district',
            'state',
            'country',
            'date_of_birth',
        ]
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),  # Use HTML5 date input for date_of_birth field
        }
        
from django import forms

class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ['title', 'content', 'notification_type', 'attachment']



class TakeAttendanceForm(forms.Form):
    attendance_date = forms.DateField(label='Select Date')
    confirm_checkbox = forms.BooleanField(
        label='Confirm Attendance',
        required=False
    )


class AttendanceRecordForm(forms.Form):
    student_id = forms.IntegerField(widget=forms.HiddenInput())
    is_present = forms.BooleanField(required=False)
    full_name = forms.CharField(widget=forms.HiddenInput())  # Add a hidden field for full name

class ViewAttendanceForm(forms.Form):
    selected_month = forms.ChoiceField(
        label='Select Month',
        choices=[(str(i), calendar.month_name[i]) for i in range(1, 13)],
        required=False
    )
    selected_year = forms.ChoiceField(
        label='Select Year',
        choices=[(str(year), str(year)) for year in range(2000, 2051)],
        required=False
    )


class EditAttendanceForm(forms.Form):
    attendance_date = forms.DateField(
        label='Select Date',
        widget=forms.DateInput(attrs={'type': 'date'}),
        input_formats=['%Y-%m-%d'],  # Specify the date format here
        required=False,
    )


from django import forms
from .models import MenuItem

class MenuItemForm(forms.ModelForm):
    class Meta:
        model = MenuItem
        fields = ['day', 'breakfast', 'lunch', 'tea', 'dinner']



from django import forms
from .models import ChangeRoomRequest, HostelAllotmentRegistration

# class ChangeRoomRequestForm(forms.ModelForm):
#     class Meta:
#         model = ChangeRoomRequest
#         fields = ['full_name', 'registration_number', 'email', 'current_hostel', 'current_room_number', 'application_reason']

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.fields['application_reason'].widget.attrs['placeholder'] = 'Write your application for room change'
#         self.fields['current_hostel'].widget = forms.TextInput(attrs={'readonly': 'readonly'})

#     def set_current_hostel(self, current_hostel_name):
#         self.fields['current_hostel'].initial = current_hostel_name
#         self.fields['current_hostel'].widget.attrs['readonly'] = True

#     def initialize_hostel_fields(self, current_hostel_name):
#         self.set_current_hostel(current_hostel_name)

#     def initialize_hostel_fields_from_instance(self, instance):
#         current_hostel_name = instance.student.hostelallotmentregistration.allotted_hostel.name
#         self.initialize_hostel_fields(current_hostel_name)

class ChangeRoomRequestForm(forms.ModelForm):
    class Meta:
        model = ChangeRoomRequest
        fields = ['full_name', 'registration_number', 'email', 'current_hostel', 'current_room_number', 'application_reason']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['application_reason'].widget.attrs['placeholder'] = 'Write your application for room change'
        self.fields['full_name'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        self.fields['registration_number'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        self.fields['email'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        self.fields['current_hostel'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        self.fields['current_room_number'].widget = forms.TextInput(attrs={'readonly': 'readonly'})

    def set_current_hostel(self, current_hostel_name):
        self.fields['current_hostel'].initial = current_hostel_name
        self.fields['current_hostel'].widget.attrs['readonly'] = True
        self.fields['current_room_number'].widget.attrs['readonly'] = True
    def initialize_hostel_fields(self, current_hostel_name):
        self.set_current_hostel(current_hostel_name)

    def initialize_hostel_fields_from_instance(self, instance):
        current_hostel_name = instance.student.hostelallotmentregistration.allotted_hostel.name
        self.initialize_hostel_fields(current_hostel_name)