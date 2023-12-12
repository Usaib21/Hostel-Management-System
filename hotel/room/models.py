from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.utils import timezone
import datetime
from django.core.validators import MaxValueValidator, MinValueValidator
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.urls import reverse 

class CustomUserManager(BaseUserManager):
    def create_user(self, registration_number, email, phone, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(registration_number=registration_number, email=email, phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, registration_number, email, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(registration_number, email, phone, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    username_validator = UnicodeUsernameValidator()

    registration_number = models.CharField(max_length=20, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    phone = models.IntegerField(blank=True, null=True, validators=[MinValueValidator(1000000000), MaxValueValidator(9999999999)])
    date_joined = models.DateTimeField(default=timezone.now)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    date = models.DateTimeField(default=timezone.now)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    objects = CustomUserManager()

    # Updated the USERNAME_FIELD to allow login with either email or registration_number
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['registration_number', 'phone']  # Include other required fields

    def clean(self):
        if not str(self.phone).isdigit():
            raise ValidationError('Phone number must contain only numeric digits.')

    def __str__(self):
        return self.registration_number

    def get_full_name(self):
        return self.registration_number

    def get_short_name(self):
        return self.registration_number

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

class Hostel(models.Model):
    name = models.CharField(max_length=50, unique=True)
    capacity = models.IntegerField(default=300)  # Set the capacity of each hostel to 300

    def __str__(self):
        return self.name
    

    def create_rooms(self):
        for floor_number in range(1, 5):
            for room_number in range(1, 31):
                room = HostelRoom.objects.create(
                    hostel=self,
                    floor_number=floor_number,
                    room_number=room_number,
                    capacity=3  # Default capacity for regular students
                )
                if self.name.startswith("GH") or self.name.startswith("BH"):
                    room.capacity = 2  # Capacity for PhD students
                room.save()
    
    def get_remaining_capacity(self):
        total_allotments = self.allotments.count()
        remaining_capacity = self.capacity - total_allotments
        return remaining_capacity

    def get_total_rooms(self):
        return self.rooms.count()

    def get_total_allotments(self):
        return self.allotments.count()  # Use the related name 'allotments'



    def get_vacancies(self):
        return self.capacity - self.get_total_allotments()

# Hostel Room Model
class HostelRoom(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.SET_NULL, null=True)
    floor_number = models.PositiveIntegerField(choices=[(i, i) for i in range(1, 5)], default=1)  # Floors 1 to 4
    room_number = models.PositiveIntegerField()
    capacity = models.IntegerField(default=3)  # Total capacity of the room (3 beds by default)
    is_phd_only = models.BooleanField(default=False)  # True if only one student is allowed (for PhD scholars)

    def __str__(self):
        return f"{self.hostel.name} - Floor {self.floor_number} - Room {self.room_number}"
    def get_vacancies(self):
        # If PhD student is in the room, vacancy is 2; otherwise, it's the default capacity (3).
        if self.is_phd_only:
            return 2
        return self.capacity

# Hostel Allotment Registration Model
class HostelAllotmentRegistration(models.Model):
    # Foreign keys to collect data from the CustomUser model
    student = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
      # New field for full name
    full_name = models.CharField(max_length=200,null=True)  # You can adjust the max_length as needed
    father_name = models.CharField(max_length=200,null=True)
    registration_number = models.CharField(max_length=20, blank=True)
    email = models.EmailField(max_length=255, blank=True)
    phone = models.CharField(max_length=15, blank=True)
    date_of_birth = models.DateField(null=True, default=None)
    terms_and_conditions = models.BooleanField(default=False)
   

    # Other fields for the registration form
    department = models.CharField(max_length=100)
    course = models.CharField(max_length=100)
    semester = models.CharField(max_length=100)
    religion = models.CharField(max_length=50)
    district = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('others', 'Others'),
    )
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    allotted_date = models.DateTimeField(default=timezone.now)  # Add the allotted_date field
    is_canceled = models.BooleanField(default=False)  # Add this field for cancellation status

    allotted_hostel = models.ForeignKey(Hostel, on_delete=models.SET_NULL, null=True, blank=True, related_name='allotments')
    allotted_room = models.ForeignKey(HostelRoom, on_delete=models.SET_NULL, null=True, blank=True)
    # Add an approval field to track the allotment request approval status
    is_approved = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.registration_number} - {self.department} - {self.semester}"

    def is_phd_scholar(self):
        return self.course == 'PHD'

    def can_be_added_to_room_with_phd_scholar(self, room):
        if not room.is_phd_only:
            return True
        return self.is_phd_scholar() and HostelAllotmentRegistration.objects.filter(allotted_room=room).count() == 1
    

class ChangeRoomRequest(models.Model):
    student = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=200, null=True)
    registration_number = models.CharField(max_length=20, blank=True)
    email = models.EmailField(max_length=255, blank=True)
    current_hostel = models.ForeignKey(Hostel, on_delete=models.SET_NULL, null=True, blank=True)
    current_room_number = models.CharField(max_length=10, blank=True)
    application_reason = models.TextField()
    is_approved = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.registration_number} - {self.full_name}"


class Bill(models.Model):
    student = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # Change this to match your Student model
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    months_stayed = models.PositiveIntegerField(default=0)
    generated_date = models.DateTimeField(auto_now_add=True)
    is_paid = models.BooleanField(default=False)
    receipt_number = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return f"{self.student.registration_number} - {self.amount}"

    def generate_receipt_number(self):
        today = datetime.datetime.now()
        date_part = today.strftime('%d%m%Y')
        counter_part = str(ReceiptNumberCounter.objects.first().get_next_receipt_number()).zfill(2)
        return date_part + counter_part

    def save(self, *args, **kwargs):
        if not self.receipt_number:
            self.receipt_number = self.generate_receipt_number()
        super().save(*args, **kwargs)


class ReceiptNumberCounter(models.Model):
    counter = models.PositiveIntegerField(default=1)

    def get_next_receipt_number(self):
        next_receipt_number = self.counter
        self.counter += 1
        self.save()
        return next_receipt_number

    class Meta:
        verbose_name_plural = 'Receipt Number Counters'


class MessPayment(models.Model):
    student = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    months_name = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    generated_date = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=False)  # To mark if the bill is paid
    receipt_number = models.CharField(max_length=20, unique=True, blank=True, null=True)

    def __str__(self):
        return f"{self.student.registration_number} - {self.months_name}"

    def generate_receipt_number(self):
        today = datetime.datetime.now()
        date_part = today.strftime('%d%m%Y')
        counter_part = str(ReceiptNumberCounter.objects.first().get_next_receipt_number()).zfill(2)
        return date_part + counter_part

    def save(self, *args, **kwargs):
        if not self.receipt_number:
            self.receipt_number = self.generate_receipt_number()
        super().save(*args, **kwargs)


class Notification(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField(blank=True, null=True)
    notification_type = models.CharField(max_length=20)
    attachment = models.FileField(upload_to='notifications/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class DailyAttendance(models.Model):
    date = models.DateField()
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE, default=1)  # Provide a default hostel ID
    students = models.ManyToManyField(HostelAllotmentRegistration, through='AttendanceRecord')


    def __str__(self):
        return f"{self.hostel.name} - {str(self.date)}"

class AttendanceRecord(models.Model):
    student = models.ForeignKey(HostelAllotmentRegistration, on_delete=models.CASCADE)
    attendance = models.ForeignKey(DailyAttendance, on_delete=models.CASCADE)
    is_present = models.BooleanField(default=False)
    

    def __str__(self):
        return f"{self.student.registration_number} - {self.attendance.date}"


class ProfilePicture(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return f'Profile Picture for {self.user.registration_number}'


class MenuItem(models.Model):
    DAY_CHOICES = [
        ('Monday', 'Monday'),
        ('Tuesday', 'Tuesday'),
        ('Wednesday', 'Wednesday'),
        ('Thursday', 'Thursday'),
        ('Friday', 'Friday'),
        ('Saturday', 'Saturday'),
        ('Sunday', 'Sunday'),
    ]

    day = models.CharField(max_length=20, choices=DAY_CHOICES)
    breakfast = models.CharField(max_length=50)
    lunch = models.CharField(max_length=50)
    tea = models.CharField(max_length=50)
    dinner = models.CharField(max_length=50)


class FeedbackAndComplaint(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    rating = models.PositiveIntegerField()
    complaint_text = models.TextField()
    submission_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'Feedback/Complaint by {self.user.registration_number} ({self.submission_date})'

