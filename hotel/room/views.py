
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from room.models import CustomUser,Hostel,HostelRoom
from datetime import datetime
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.contrib.auth import views as auth_views
from django.db.models import Q
from django.contrib.auth.hashers import make_password,check_password
from django.db.utils import IntegrityError
from django.contrib import messages 
from .my_custom_backends import CustomAuthenticationBackend
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMessage
from .forms import EmailSettingsForm
from django.conf import settings



from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.shortcuts import render, redirect, get_object_or_404



UserModel = get_user_model()
# Create your views here.
# @login_required
# def HomePage(request):
#     notifications = ["Notification 1", "Notification 2"]  # Sample notifications, replace with real notifications from the backend
#     context = {'notifications': notifications}
#     return render(request, 'home.html', context)
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import HostelAllotmentRegistration

@login_required
def HomePage(request):
    user = request.user
    full_name = "N/A"

    # Check if the user is logged in
    if user.is_authenticated:
        # Check if the user has a HostelAllotmentRegistration
        try:
            hostel_allotment = HostelAllotmentRegistration.objects.get(student=user)
            full_name = hostel_allotment.full_name
        except HostelAllotmentRegistration.DoesNotExist:
            print("HostelAllotmentRegistration not found for user:", user.registration_number)

    # Pass the full_name to the template
    context = {'notifications': ["Notification 1", "Notification 2"], 'full_name': full_name}
    return render(request, 'home.html', context)


def SignupPage(request):
    if request.method == 'POST':
        registration_number = request.POST.get('registration-number')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        password = request.POST.get('password1')
        confirm_password = request.POST.get('password2')

        if password != confirm_password:
            messages.error(request, "Your password and confirm password are not the same!")
            return redirect('signup')  # Redirect back to the signup page with the error message

        # Check if the registration number starts with 'IUST'
        if not registration_number.startswith('IUST'):
           messages.error(request, "Your Registration Number is not Valid!")
           return redirect('signup')  # Redirect back to the signup page with the error message
        
        try:
            # Attempt to convert the phone number to an integer
            phone = int(phone)
            if len(str(phone)) != 10:
                raise ValueError("Phone number must be 10 digits long.")
        except ValueError:
            messages.error(request, "Phone number must be a numeric value with a length of 10 digits.")
            return redirect('signup')  # Redirect back to the signup page with the error message

        # Hash the password before saving
        hashed_password = make_password(password)

        try:
            # Check if a user with the same registration number or email already exists
            user = CustomUser.objects.filter(Q(registration_number=registration_number) | Q(email=email)).first()

            if user is not None:
                messages.error(request, "A user with the same registration number or email already exists.")
                return redirect('signup')  # Redirect back to the signup page with the error message
            else:
                # Save the new user to the database
                my_user = CustomUser(registration_number=registration_number, email=email, phone=phone, password=hashed_password, date=datetime.today())
                my_user.save()
                messages.success(request, "You are registered successfully!!!.")
                return redirect('login')
        except IntegrityError as e:
            print("An error occurred while saving the user:", e)
            return HttpResponse("An error occurred while saving the user. Please try again later.")
                    
    return render(request, 'signup.html')


def LoginPage(request):
    if request.method == 'POST':
        login_identifier = request.POST.get('login_identifier')
        password = request.POST.get('password1')

        # Retrieve the user object based on the login_identifier (registration number or email)
        user = CustomUser.objects.filter(Q(registration_number=login_identifier) | Q(email=login_identifier)).first()

        if user is not None:
            # Check if the provided password matches the hashed password in the database
            if user.check_password(password):
                # If the password is correct, authenticate the user and log them in
                authenticated_user = authenticate(request, login_identifier=login_identifier, password=password)

                if authenticated_user is not None:
                    login(request, authenticated_user)
                    messages.success(request, "You are logged_In successfully!!!.")
                    return redirect('home')  # Redirect to the home page after successful login
                else:
                    messages.error(request, "An error occurred during authentication. Please try again later.")
            else:
                messages.error(request, "Invalid credentials")
        else:
            messages.error(request, "Invalid credentials")

    return render(request, 'login.html')


def LogoutPage(request):
    logout(request)
    return redirect('login')


#     Class-based password reset views
# - PasswordResetView sends the mail
# - PasswordResetDoneView shows a success message for the above
# - PasswordResetConfirmView checks the link the user clicked and
#   prompts for a new password
# - PasswordResetCompleteView shows a success message for the above


class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {"title": self.title, "subtitle": None, **(self.extra_context or {})}
        )
        return context


class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = "password_reset/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "password_reset/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "password_reset/password_reset_form.html"
    title = _("Password reset")
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_done.html"
    title = _("Password reset sent")


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "password_reset/password_reset_confirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = "password_reset/password_reset_complete.html"
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy("password_change_done")
    template_name = "password_reset/password_change_form.html"
    title = _("Password change")

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = "password_reset/password_change_done.html"
    title = _("Password change successful")

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    

    # views.py


def email_settings(request):
    if request.method == 'POST':
        form = EmailSettingsForm(request.POST)
        if form.is_valid():
            # Save the email settings to the Django settings module
            settings.EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
            settings.EMAIL_HOST = form.cleaned_data['email_host']
            settings.EMAIL_PORT = form.cleaned_data['email_port']
            settings.EMAIL_USE_TLS = True  # You can use TLS if supported by your email provider
            settings.EMAIL_HOST_USER = form.cleaned_data['email_username']
            settings.EMAIL_HOST_PASSWORD = form.cleaned_data['email_password']
            settings.DEFAULT_FROM_EMAIL = form.cleaned_data['default_from_email']
            return render(request, 'email_settings_saved.html')
    else:
        form = EmailSettingsForm()
    return render(request, 'email_settings_form.html', {'form': form})



from django.shortcuts import render, redirect
from .forms import HostelAllotmentRegistrationForm
from django.contrib import messages

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser, Hostel, HostelRoom, HostelAllotmentRegistration
from django.http import JsonResponse



def get_available_hostel_for_gender(gender):
    try:
        return Hostel.objects.filter(gender_allotment__in=[gender, 'both'], capacity__gt=0).first()
    except Hostel.DoesNotExist:
        return None
    
def terms_and_conditions(request):
    return render(request, 'terms_and_conditions.html')



from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from .models import HostelAllotmentRegistration, Hostel
from .forms import HostelAllotmentRegistrationForm

def hostel_allotment_registration(request):
    if request.method == 'POST':
        form = HostelAllotmentRegistrationForm(request.POST)
        if form.is_valid():
            registration = form.save(commit=False)
            registration.student = request.user

            # Check if the student already has an allotment request
            if HostelAllotmentRegistration.objects.filter(student=registration.student).exists():
                messages.error(request, 'You have already submitted a hostel allotment request.')
                return redirect('home')

            # Save the allotment request
            registration.save()

            # Send a success message to the student
            messages.success(request, 'Your hostel allotment request has been submitted successfully. Wait until admin approves your request.')

            # Send an email to the student
            student_email_subject = 'Hostel Allotment Request Submitted'
            student_email_message = f'Dear Student,\n\nYour hostel allotment request of Registration Number: {registration.registration_number} has been submitted successfully. Wait until administration approves your request. We will inform you through email.\n\nThank You,\nTeam IUST'
            student_email_from = 'peerusaib111@gmail.com'  # Replace with your email
            student_email_recipient_list = [registration.student.email]
            send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=True)

            return redirect('home')

    # Rest of the code remains the same
    else:
        # Similar logic as before to pre-fill the form with user's profile data and set the 'readonly' attribute
        user = request.user
        initial_data = {
            'email': user.email,
            'registration_number': user.registration_number,
            'phone': user.phone,
        }
        form = HostelAllotmentRegistrationForm(initial=initial_data)

        for field_name in initial_data:
            form.fields[field_name].widget.attrs['readonly'] = True

    return render(request, 'hostel_allotment_registration.html', {'form': form})


def approve_allotment_request(request, registration_id):
    registration = HostelAllotmentRegistration.objects.get(pk=registration_id)

    if registration.is_approved:
        messages.error(request, 'Hostel allotment for this student is already approved.')
        return redirect('admin-approval-failure')

    gender = registration.gender
    hostel = get_available_hostel_for_gender(gender)

    if not hostel:
        messages.error(request, 'No vacancy available in any hostel for the selected gender. Please wait until there is a vacancy.')
        return redirect('admin-approval-failure')

    registration.allotted_hostel = hostel
    registration.allotted_date = timezone.now()
    registration.is_approved = True
    registration.save()

    student_email_subject = 'Hostel Allotment Approved'
    student_email_message = f'Dear Student,\n\nYou have been allotted {hostel.name} at Islamic University of Science and Technology. You are now a resident of {hostel.name}. Your bill is generated for the hostel and mess from today onwards, so you can join the hostel now.\n\nThank you,\nTeam IUST'
    student_email_from = 'peerusaib111@gmail.com'
    student_email_recipient_list = [registration.student.email]
    send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=True)

    # Remove the redirect and just display a success message
    messages.success(request, 'Hostel allotment approved successfully.')
    return None 


def reject_hostel_allotment(request, registration_id):
    registration = HostelAllotmentRegistration.objects.get(pk=registration_id)

    if registration.is_rejected:
        messages.error(request, 'Hostel allotment for this student is already rejected.')
    else:
        # Set the rejection status and save the object
        registration.is_rejected = True
        registration.save()

        # Send an email to the student for rejection
        student_email_subject = 'Hostel Allotment Request Rejected'
        student_email_message = f'Dear Student,\n\nYour hostel allotment request of Registration Number: {registration.registration_number} has been cancelled by administration.\n\nReasons:\n1. Either there is no vacancy in any hostel.\n2. You are a resident of nearby locations to the university.\n\nThank you,\nTeam IUST'
        student_email_from = 'peerusaib111@gmail.com'  # Replace with your email
        student_email_recipient_list = [registration.student.email]

        # Send the rejection email
        send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=False)

        messages.success(request, f'Hostel allotment for {registration.full_name} is rejected.')

    return None 


def perform_hostel_allotment(request, registration):
    if registration.student.allotted_hostel:
        messages.error(request, 'This student is already allotted a hostel.')
        return False

    gender = registration.gender
    hostel = get_available_hostel_for_gender(gender)

    if not hostel:
        messages.error(request, 'No vacancy available in any hostel for the selected gender. Please wait until there is a vacancy.')
        return False

    registration.allotted_hostel = hostel
    registration.allotted_date = timezone.now()
    registration.is_approved = True
    registration.save()

    return True



def hostel_details(request):
    # Get the current user
    user = request.user

    # Check if the user has a hostel allotment
    allotment = HostelAllotmentRegistration.objects.filter(student=user).first()

    if allotment:
        # Redirect to the registration success page with the allotment's PK
        return redirect('registration_success', pk=allotment.pk)
    else:
        # Display a message and redirect to the home page
        messages.warning(request, "You do not have any hostel allotment yet. Please allot a hostel first.")
        return redirect('home')  


def get_available_rooms(hostel):
    # Return a list of available rooms in the given hostel
    return HostelRoom.objects.filter(hostel=hostel, capacity__gt=0)


def already_allotted(request, allotment_id):
    allotment = get_object_or_404(HostelAllotmentRegistration, id=allotment_id)
    return render(request, 'registration_success.html', {'allotment': allotment})  


def registration_success(request, pk):
    allotment = get_object_or_404(HostelAllotmentRegistration, pk=pk)
    is_phd_scholar = allotment.is_phd_scholar()  # Get the is_phd_scholar value from the allotment
    available_rooms = get_available_rooms(allotment.allotted_hostel, is_phd_scholar)  # Pass both arguments
    hostels = Hostel.objects.all()

    hostel_colors = {
        "BH1": "red-bg",
        "GH1": "blue-bg",
        "BH2": "green-bg",
        "GH2": "yellow-bg",
        # Add more hostels and colors as needed
    }
   
    context = {
        'allotment': allotment,
        'hostels': hostels,
        'hostel_colors': hostel_colors,
    }
    return render(request, 'registration_success.html', context)


def get_available_hostel_for_gender(gender):
    # Define the hostel names and capacities for males and females
    male_hostels = ['BH1', 'BH2']  # List of male hostels in priority order
    female_hostels = ['GH1', 'GH2']  # List of female hostels in priority order

    # Get the count of alloted students in each male hostel
    male_hostel_counts = [HostelAllotmentRegistration.objects.filter(allotted_hostel__name=hostel).count() for hostel in male_hostels]

    # Get the count of alloted students in each female hostel
    female_hostel_counts = [HostelAllotmentRegistration.objects.filter(allotted_hostel__name=hostel).count() for hostel in female_hostels]

    if gender == 'male':
        for index, hostel in enumerate(male_hostels):
            capacity = Hostel.objects.get(name=hostel).capacity
            if male_hostel_counts[index] < capacity:
                return Hostel.objects.get(name=hostel)

    elif gender == 'female':
        for index, hostel in enumerate(female_hostels):
            capacity = Hostel.objects.get(name=hostel).capacity
            if female_hostel_counts[index] < capacity:
                return Hostel.objects.get(name=hostel)

    # Return None if no hostel is available for the given gender and capacity is full for all hostels
    return None

    from django.http import JsonResponse


from django.shortcuts import render
from .models import Hostel, HostelRoom, HostelAllotmentRegistration


def available_rooms(request):
    user = request.user
    try:
        allotment = user.hostelallotmentregistration_set.first()
        allotted_hostel = allotment.allotted_hostel
        is_phd_scholar = allotment.is_phd_scholar
        available_rooms = get_available_rooms(allotted_hostel, is_phd_scholar)

        context = {
            'allotment': allotment,
            'available_rooms': available_rooms,
        }
    except AttributeError:
        # Handle case when user doesn't have a hostel allotment
        context = {
            'allotment': None,
            'available_rooms': None,
        }
    return render(request, 'available_rooms.html', context)



from django.shortcuts import render, redirect, Http404,get_object_or_404
from django.contrib import messages
from .models import HostelRoom, HostelAllotmentRegistration, Hostel


def change_room(request):
    if request.method == 'POST':
        user = request.user
        new_room_id = request.POST.get('new_room')
        
        if new_room_id:
            new_room = HostelRoom.objects.get(pk=new_room_id)

            # Your room change logic here
            try:
                allotment = user.hostelallotmentregistration_set.first()

                if not allotment:
                    messages.error(request, "You have not been allotted a room.")
                else:
                    if new_room.capacity - new_room.hostelallotmentregistration_set.count() < 1:
                        messages.error(request, 'New room is already full. Please choose another room.')
                    else:
                        if allotment.allotted_room:
                            previous_room = allotment.allotted_room
                            previous_room.capacity += 1
                            previous_room.save()

                        allotment.allotted_room = new_room
                        allotment.save()

                        new_room.capacity -= 1
                        new_room.save()

                        messages.success(request, f'You have successfully changed your room. Your new room is on Floor {new_room.floor_number}, Room {new_room.room_number}.')

            except AttributeError:
                messages.error(request, "You have not been allotted a room.")
            
    return redirect('available_rooms_for_change', hostel_id=allotment.allotted_hostel.id, floor_number=allotment.allotted_room.floor_number)  # Redirect to the available rooms page



from django.contrib.auth.decorators import login_required

@login_required        
def available_floors_for_change(request, hostel_id):
    user = request.user
    allotment = user.hostelallotmentregistration_set.first()

    if not allotment or allotment.allotted_hostel.id != int(hostel_id):
        messages.error(request, "You are not a student/boarder of this hostel.")
        return redirect('available_rooms')

    hostel = Hostel.objects.get(id=int(hostel_id))
    available_floors = []

    for floor_number in range(1, 5):  # Assuming there are floors numbered from 1 to 4
        rooms_on_floor = HostelRoom.objects.filter(hostel=hostel, floor_number=floor_number, capacity__gt=0)
        if rooms_on_floor.exists():
            available_floors.append(floor_number)

    context = {
        'allotment': allotment,
        'hostel': hostel,
        'available_floors': available_floors,
    }

    return render(request, 'available_floors_for_change.html', context)



def available_rooms_for_change(request, hostel_id, floor_number):
    user = request.user
    allotment = user.hostelallotmentregistration_set.first()

    if not allotment or allotment.allotted_hostel.id != int(hostel_id):
        messages.error(request, "You are not a student/boarder of this hostel.")
        return redirect('available_rooms')

    hostel = get_object_or_404(Hostel, id=int(hostel_id))
    floor_number = int(floor_number)

    rooms_on_floor = HostelRoom.objects.filter(hostel=hostel, floor_number=floor_number, capacity__gt=0)

    context = {
        'hostel': hostel,
        'floor_number': floor_number,
        'rooms_on_floor': rooms_on_floor,
        'allotment': allotment,
    }

    return render(request, 'available_rooms_for_change.html', context)

# views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import ChangeRoomRequest, HostelAllotmentRegistration
from .forms import ChangeRoomRequestForm
from django.core.mail import send_mail
from django.db import transaction  # Import the transaction module


def before_change_room(request):
    user = request.user

    # Check if the user has a room allotment
    hostel_allotment = HostelAllotmentRegistration.objects.filter(student=user).first()
    if not hostel_allotment or not hostel_allotment.allotted_room:
        messages.error(request, "You don't have any room yet. Please choose a room first.")
        return redirect('registration_success', pk=hostel_allotment.pk)

    # Check if there is an existing change room request
    existing_request = ChangeRoomRequest.objects.filter(student=user, is_approved=True).first()

    if existing_request:
        # Redirect to available_floors_for_change with the hostel_id
        hostel_id = existing_request.current_hostel.id
        url = reverse('available_floors_for_change', kwargs={'hostel_id': hostel_id})
        return redirect(url)

    # Check if there is a pending change room request
    pending_request = ChangeRoomRequest.objects.filter(student=user, is_approved=False).first()

    if pending_request:
        messages.warning(request, "You already have a pending change room request.")
        return redirect('registration_success', pk=hostel_allotment.pk)

    form = ChangeRoomRequestForm(initial={
        'full_name': hostel_allotment.full_name,
        'registration_number': hostel_allotment.registration_number,
        'email': hostel_allotment.email,
        'current_hostel': hostel_allotment.allotted_hostel.name,
        'current_room_number': hostel_allotment.allotted_room.room_number,
    })

    # Make only specific fields read-only
    readonly_fields = ['full_name', 'registration_number', 'email', 'current_hostel', 'current_room_number']
    for field_name in form.fields:
        if field_name in readonly_fields:
            form.fields[field_name].widget.attrs['readonly'] = True

    if request.method == 'POST':
        form = ChangeRoomRequestForm(request.POST)
        if form.is_valid():
            request_data = form.cleaned_data
            
            change_request = ChangeRoomRequest.objects.create(
                student=user,
                full_name=request_data['full_name'],
                registration_number=request_data['registration_number'],
                email=request_data['email'],
                current_hostel=request_data['current_hostel'],
                current_room_number=request_data['current_room_number'],
                application_reason=request_data['application_reason'],
            )

            # Notify the student via email
            student_email_subject = 'Change Room Request Submitted'
            student_email_message = f'Dear {change_request.full_name},\n\nYour change room request has been submitted successfully. We will inform you once it is approved.\n\nThank you,\nTeam IUST'
            student_email_from = 'peerusaib111@gmail.com'
            student_email_recipient_list = [user.email]
            send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=True)

            messages.success(request, "Your room change request has been submitted successfully. We will inform you through email.")
            return redirect('registration_success', pk=hostel_allotment.pk)
        else:
            messages.error(request, "Form submission failed. Please check the errors below.")

    return render(request, 'before_change_room.html', {'form': form})


@transaction.atomic  # Use the atomic transaction decorator
def approved_change_room_request(request, request_ids):
    request_ids = request_ids.split(',')  # Convert string of IDs to a list
    change_requests = ChangeRoomRequest.objects.filter(id__in=request_ids)

    for change_request in change_requests:
        # Your existing approval logic
        change_request.is_approved = True
        change_request.save()


        # Notify the student via email
        student_email_subject = 'Change Room Request Approved'
        student_email_message = f'Dear {change_request.full_name},\n\nYour change room request has been approved by the administration. You can now proceed to change your room.\n\nThank you,\nTeam IUST'
        student_email_from = 'peerusaib111@gmail.com'
        student_email_recipient_list = [change_request.student.email]
        
        try:
            send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=True)
        except Exception as e:
            # Print or log the exception for debugging
            print(f"Error sending approval email: {e}")

    messages.success(request, f'Successfully approved {len(request_ids)} change room requests.')
    return redirect('admin:room_changeroomrequest_changelist')

@transaction.atomic  # Use the atomic transaction decorator
def reject_change_room_request(request, request_ids):
    request_ids = request_ids.split(',')  # Convert string of IDs to a list
    change_requests = ChangeRoomRequest.objects.filter(id__in=request_ids)

    for change_request in change_requests:
        # Your existing rejection logic
        change_request.is_rejected = True
        change_request.save()


        student_email_subject = 'Change Room Request Rejected'
        student_email_message = f'Dear {change_request.full_name},\n\nYour change room request has been rejected by the administration. Unfortunately, you cannot proceed with the room change at this time.\n\nRejection reasons:\n1. There are no available rooms in your hostel for room change.\n2. You have changed your room multiple times.\n\nThank you,\nTeam IUST'
        student_email_from = 'peerusaib111@gmail.com'
        student_email_recipient_list = [change_request.student.email]
        
        try:
            send_mail(student_email_subject, student_email_message, student_email_from, student_email_recipient_list, fail_silently=True)
        except Exception as e:
            # Print or log the exception for debugging
            print(f"Error sending rejection email: {e}")

    messages.warning(request, f'Successfully rejected {len(request_ids)} change room requests.')
    return redirect('admin:room_changeroomrequest_changelist')



from django.http import JsonResponse
from django.db import transaction
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponse
from django.template.loader import render_to_string

# def cancel_hostel(request):
#     if request.method == 'POST':
#         user = request.user
#         allotment = HostelAllotmentRegistration.objects.filter(student=user).first()
#         print("allotment")
#         print(allotment)

#         if allotment:
#             try:
#                 with transaction.atomic():
#                     # Delete related room allotment if exists
#                     room_allotment = allotment.allotted_room
#                     room = room_allotment.hostel
#                     print("room_allotment")
#                     print(room_allotment)
#                     # if room_allotment:
#                     #     room = room_allotment
#                     #     print("room")
#                     #     print(room)
#                     #     room_allotment.delete()
#                     #     # room.capacity += 1
#                     #     room.save()

#                     # # Delete the allotment record
#                     allotted_hostel = allotment.allotted_hostel
#                     print("allotted_hostel")
#                     print(allotted_hostel)
#                     allotment.delete()
#                     room.capacity += 1

#                      # Call the function to handle cancellation and bill
#                     handle_hostel_cancellation(allotment)

#                     messages.success(request, "You have successfully cancelled your hostel allotment.")
#                     return JsonResponse({'success': True})
#             except Exception as e:
#                 print("Error cancelling hostel:", e)
#                 messages.error(request, "An error occurred while cancelling the hostel.")
#                 return JsonResponse({'success': False, 'error': 'An error occurred while cancelling the hostel.'})
#         else:
#             messages.error(request, "No hostel allotment found for cancellation.")
#             return JsonResponse({'success': False, 'error': 'No hostel allotment found for cancellation.'})

#     return JsonResponse({'success': False, 'error': 'Invalid request method.'})


from django.db import transaction
from django.http import JsonResponse
from django.contrib import messages
from .models import HostelAllotmentRegistration, HostelRoom

def cancel_hostel(request):
    if request.method == 'POST':
        user = request.user
        allotment = HostelAllotmentRegistration.objects.filter(student=user).first()
        print("cancel hostel is called")
        print("allotment")
        print(allotment)

        if allotment:
            try:
                with transaction.atomic():
                    # Delete related room allotment if exists
                    room_allotment = allotment.allotted_room
                    room = room_allotment.hostel
                    print("room_allotment")
                    print(room_allotment)
                    
                    # # Delete the allotment record
                    allotted_hostel = allotment.allotted_hostel
                    print("allotted_hostel")
                    print(allotted_hostel)
                    allotment.delete()

                    # Update room's capacity
                    if room_allotment:
                        room_allotment.capacity += 1
                        print("room_allotment.capacity ",room_allotment.capacity )
                        room_allotment.save()
                        print("room_allotment",room_allotment )
                        

                    # Call the function to handle cancellation and bill
                    handle_hostel_cancellation(allotment)

                    messages.success(request, "You have successfully cancelled your hostel allotment.")
                    return JsonResponse({'success': True})
            except Exception as e:
                print("Error cancelling hostel:", e)
                messages.error(request, "An error occurred while cancelling the hostel.")
                return JsonResponse({'success': False, 'error': 'An error occurred while cancelling the hostel.'})
        else:
            messages.error(request, "No hostel allotment found for cancellation.")
            return JsonResponse({'success': False, 'error': 'No hostel allotment found for cancellation.'})

    return JsonResponse({'success': False, 'error': 'Invalid request method.'})




# def cancel_hostel(request):
#     if request.method == 'POST':
#         user = request.user
#         allotment = HostelAllotmentRegistration.objects.filter(student=user).first()

#         if allotment:
#             try:
#                 with transaction.atomic():
#                     # Delete related room allotment if exists
#                     room_allotment = RoomAllotment.objects.filter(student=user).first()
#                     if room_allotment:
#                         room = room_allotment.room
#                         room_allotment.delete()
#                         room.capacity += 1
#                         room.save()

#                     # Delete the allotment record
#                     allotted_hostel = allotment.allotted_hostel
#                     allotment.delete()

#                     messages.success(request, "You have successfully cancelled your hostel allotment.")
#                     return JsonResponse({'success': True})
#             except Exception as e:
#                 print("Error cancelling hostel:", e)
#                 messages.error(request, "An error occurred while cancelling the hostel.")
#                 return JsonResponse({'success': False, 'error': 'An error occurred while cancelling the hostel.'})
#         else:
#             messages.error(request, "No hostel allotment found for cancellation.")
#             return JsonResponse({'success': False, 'error': 'No hostel allotment found for cancellation.'})

#     return JsonResponse({'success': False, 'error': 'Invalid request method.'})




def allot_room(request, room_id):
    room = get_object_or_404(HostelRoom, pk=room_id)
    student = request.user
    allotment = HostelAllotmentRegistration.objects.filter(student=student, allotted_room__isnull=False).first()

    if allotment is None or allotment.allotted_room is None:
        # No room allotted yet, proceed with allotment
        if room.capacity > 0:
            # Create or update the allotment record with student details
            allotment, created = HostelAllotmentRegistration.objects.get_or_create(student=student)
            allotment.allotted_room = room
            allotment.save()

            # Update room's occupancy count
            room.capacity -= 1
            room.save()

            messages.success(request, f'Room has been successfully allotted to you.Your room is on Floor {room.floor_number}, Room {room.room_number}.')
        else:
            messages.error(request, f'Room {room.floor_number}{room.room_number} is already full and cannot be allotted.')
    else:
        messages.error(request, 'You can only select one room.')

    # Redirect back to the appropriate available rooms page
    redirect_url = reverse('available_rooms_on_floor', args=[room.hostel.id, room.floor_number])
    return redirect(redirect_url)



def room_details(request, room_id):
    room = get_object_or_404(HostelRoom, pk=room_id)
    occupants = HostelAllotmentRegistration.objects.filter(allotted_room=room)
    
    occupant_details = []
    for occupant in occupants:
        print("Occupant Full Name:", occupant.full_name)
        print("Occupant Department:", occupant.department)
        print("Occupant Course:", occupant.course)
        
        occupant_details.append({
            'full_name': occupant.full_name,
            'department': occupant.department,
            'course': occupant.course,
        })
    allotment = HostelAllotmentRegistration.objects.filter(allotted_room=room).first()
    context = {
        'room': room,
        'occupant_details': occupant_details,
        'allotment': allotment,
    }
    
    return render(request, 'room_details.html', context)




# //def room_details(request, room_id):
#     room = get_object_or_404(HostelRoom, pk=room_id)
#     occupants = HostelAllotmentRegistration.objects.filter(allotted_room=room)

#     # Get occupant details (full name, department, course) for each occupant
#     occupant_details = []
#     for occupant in occupants:
#         occupant_details.append({
#             'full_name': occupant.student.get_full_name(),
#             'department': occupant.department,
#             'course': occupant.course,
#         })

#     return render(request, 'room_details.html', {'room': room, 'occupant_details': occupant_details})


def display_available_rooms(request, allotment_id):
    allotment = get_object_or_404(HostelAllotmentRegistration, pk=allotment_id)
    is_phd_scholar = allotment.is_phd_scholar()  # Get the value of is_phd_scholar
    available_rooms = get_available_rooms(allotment.allotted_hostel, is_phd_scholar)
    context = {
        'allotment': allotment,
        'available_rooms': available_rooms,
    }
    return render(request, 'registration_success.html', context)


def get_available_rooms(hostel, is_phd_scholar):
    if is_phd_scholar:
        return HostelRoom.objects.filter(hostel=hostel, capacity__gt=0, is_phd_only=True)
    else:
        return HostelRoom.objects.filter(hostel=hostel, capacity__gt=0)


def available_hostels(request):
    hostels = Hostel.objects.all()
    context = {'hostels': hostels}
    return render(request, 'available_hostels.html', context)


# def available_floors(request, hostel_id):
#     hostel = get_object_or_404(Hostel, pk=hostel_id)
#     floors = range(1, 5)  # Assuming you have floors numbered from 1 to 4
#     context = {
#         'hostel': hostel,
#         'floors': floors,
#     }
#     return render(request, 'available_floors.html', context)



def get_available_floors(request, hostel_id):
    hostel = get_object_or_404(Hostel, pk=hostel_id)
    floors = range(1, 5)  # Replace this with your actual logic to get available floors
    floor_colors = {
        1: 'red-bg',
        2: 'blue-bg',
        3: 'green-bg',
        4: 'yellow-bg',
    }
    
    context = {
        'hostel': hostel,
        'floors': floors,
        'floor_colors': floor_colors,
    }
    return render(request, 'available_floors.html', context)


def available_rooms_on_floor(request, hostel_id, floor_number):
    hostel = get_object_or_404(Hostel, pk=hostel_id)
    floor_number = int(floor_number)
    
    student = request.user
    allotment = HostelAllotmentRegistration.objects.filter(student=student).first()

    if allotment is None or allotment.allotted_hostel != hostel:
        # Student is not allotted the requested hostel, display an error message
        # "You are not a boarder of this hostel. You can't go there."
        messages.error(request, 'You are not a student/boarder of this hostel.')
        return redirect('registration_success', pk=allotment.pk)

    rooms_on_floor = HostelRoom.objects.filter(hostel=hostel, floor_number=floor_number, capacity__gt=0)
    context = {
        'hostel': hostel,
        'floor_number': floor_number,
        'rooms_on_floor': rooms_on_floor,
        'allotment': allotment, 
    }
    return render(request, 'available_rooms_on_floor.html', context)

# from django.http import JsonResponse

# def get_available_hostels(request):
#     hostels = Hostel.objects.all()
#     hostel_data = [{'id': hostel.id, 'name': hostel.name} for hostel in hostels]
#     return JsonResponse({'hostels': hostel_data})


def available_floors(request, hostel_id):
    hostel = get_object_or_404(Hostel, pk=hostel_id)
    floors = range(1, 5)  # Replace this with your actual logic to get available floors
    floor_colors = {
        1: 'red-bg',
        2: 'blue-bg',
        3: 'green-bg',
        4: 'yellow-bg',
    }
    
    context = {
        'hostel': hostel,
        'floors': floors,
        'floor_colors': floor_colors,
    }
    return JsonResponse({'floors': list(floors)})

# Update this import at the top of your views.py
from django.http import JsonResponse

# Update the view name to available_rooms_on_floor_for_attendance
# def available_rooms_on_floor_for_attendance(request, hostel_id, floor_number):
#     try:
#         hostel = Hostel.objects.get(pk=hostel_id)
#         rooms_on_floor = HostelRoom.objects.filter(hostel=hostel, floor_number=floor_number)

#         available_rooms = []
#         for room in rooms_on_floor:
#             if room.capacity > 0:
#                 available_rooms.append({
#                     'id': room.id,
#                     'details': f'Floor {room.floor_number}, Room {room.room_number}',
#                     'registration_number': room.allotted_room.registration_number if room.allotted_room else '',
#                     'full_name': room.allotted_room.full_name if room.allotted_room else '',
#                 })

#         return JsonResponse({'rooms': available_rooms})
#     except Hostel.DoesNotExist:
#         return JsonResponse({'error': 'Hostel not found'}, status=404)
#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)



from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from .models import CustomUser, HostelAllotmentRegistration, Bill
from num2words import num2words



def amount_to_words(amount):
    return num2words(amount, to='currency', lang='en_IN').replace(' and', ',')


def generate_hostel_bill(student, months_stayed):
    bill_amount = calculate_bill_amount(months_stayed)
    Bill.objects.create(student=student, amount=bill_amount, months_stayed=months_stayed)


def calculate_remaining_months(session_months, current_month):
    return [month for month in session_months if month >= current_month]

def calculate_bill_amount(months_stayed):
    base_amount = 1083
    return base_amount * months_stayed

def hostel_payments(request):
    user = request.user
    student = CustomUser.objects.get(registration_number=user.registration_number)

    allotment = None  # Initialize allotment to None

    try:
        allotment = HostelAllotmentRegistration.objects.get(student=student)
    except HostelAllotmentRegistration.DoesNotExist:
        pass  # No allotment, so leave 'allotment' as None

    current_date = timezone.now().date()

    if allotment:
        allotment_date = allotment.allotted_date.date()
        current_month = current_date.month

        # Determine the session for billing
        session_1_months = [2, 3, 4, 5, 6, 7]
        session_2_months = [8, 9, 10, 11, 12, 1]  # January of next year is represented as 1

        if current_month in session_1_months:
            remaining_months = calculate_remaining_months(session_1_months, current_month)
        else:
            remaining_months = calculate_remaining_months(session_2_months, current_month)

        months_stayed = (current_date.year - allotment_date.year) * 12 + current_date.month - allotment_date.month + 1

        # Check if a bill for the current session already exists
        current_session_bill = Bill.objects.filter(student=student, months_stayed=months_stayed).first()

        if not current_session_bill:  # No bill for the current session, create one

            # Check if the student allots hostel at the start of the session (August or February)
            if allotment_date.month == 8 or allotment_date.month == 2:
                bill_amount = 6500  # Full bill amount
            else:
                # Calculate bill based on remaining months, including the current month
                bill_amount = calculate_bill_amount(len(remaining_months) + 1)  # Adding 1 for the current month

            try:
                bill = Bill.objects.get(student=student, is_paid=False)
                bill.amount = bill_amount
                bill.save()
            except Bill.DoesNotExist:
                Bill.objects.create(student=student, amount=bill_amount, months_stayed=months_stayed)

        if allotment.is_canceled:
            print("Allotment is canceled. Calling handle_hostel_cancellation.")
            handle_hostel_cancellation(allotment)
        else:
            print("Allotment is not canceled. Skipping handle_hostel_cancellation.")

    bills = Bill.objects.filter(student=student)

    context = {'allotment': allotment, 'bills': bills}
    print("Context:", context)
    return render(request, 'hostel_payment.html', context)


# def hostel_payments(request):
#     user = request.user
#     student = CustomUser.objects.get(registration_number=user.registration_number)

#     allotment = None  # Initialize allotment to None

#     try:
#         allotment = HostelAllotmentRegistration.objects.get(student=student)
#     except HostelAllotmentRegistration.DoesNotExist:
#         pass  # No allotment, so leave 'allotment' as None

#     current_date = timezone.now().date()

#     if allotment:
#         allotment_date = allotment.allotted_date.date()
#         current_month = current_date.month

#         # Determine the session for billing
#         session_1_months = [2, 3, 4, 5, 6, 7]
#         session_2_months = [8, 9, 10, 11, 12, 1]  # January of next year is represented as 1

#         if current_month in session_1_months:
#             remaining_months = calculate_remaining_months(session_1_months, current_month)
#         else:
#             remaining_months = calculate_remaining_months(session_2_months, current_month)

#         months_stayed = (current_date.year - allotment_date.year) * 12 + current_date.month - allotment_date.month + 1

#         # Check if the student allots hostel at the start of the session (August or February)
#         if allotment_date.month == 8 or allotment_date.month == 2:
#             bill_amount = 6500  # Full bill amount
#         else:
#             # Calculate bill based on remaining months, including the current month
#             bill_amount = calculate_bill_amount(len(remaining_months) + 1)  # Adding 1 for the current month

#         try:
#             bill = Bill.objects.get(student=student, is_paid=False)
#             bill.amount = bill_amount
#             bill.save()
#         except Bill.DoesNotExist:
#             Bill.objects.create(student=student, amount=bill_amount, months_stayed=months_stayed)

#         if allotment.is_canceled:
#             print("Allotment is canceled. Calling handle_hostel_cancellation.")
#             handle_hostel_cancellation(allotment)
#         else:
#             print("Allotment is not canceled. Skipping handle_hostel_cancellation.")

#     bills = Bill.objects.filter(student=student)

#     context = {'allotment': allotment, 'bills': bills}
#     print("Context:", context)
#     return render(request, 'hostel_payment.html', context)





# import logging

# logger = logging.getLogger(__name__)

# def handle_hostel_cancellation(allotment_id):
#     logger.debug("handle_hostel_cancellation function is being executed.")
#     print(f"Attempting to cancel allotment {allotment_id}")
#     current_date = timezone.now().date()
#     allotment_date = allotment_id.allotted_date.date()

#     # Calculate months stayed
#     months_stayed = (current_date.year - allotment_date.year) * 12 + current_date.month - allotment_date.month + 1

#     # Determine the session for billing
#     session_1_months = [2, 3, 4, 5, 6, 7]
#     session_2_months = [8, 9, 10, 11, 12, 1]  # January of next year is represented as 1

#     current_month = current_date.month

#     # Check which session the current month belongs to
#     if current_month in session_1_months:
#         session_months = session_1_months  # Set session_months to the first session
#     else:
#         session_months = session_2_months  # Set session_months to the second session

#     # Check if cancellation month is the same as allotment month
#     if current_month == allotment_date.month:
#         bill_amount = months_stayed * 1083  # Create a bill for the number of months stayed
#     else:
#         # Calculate the number of months stayed in the session, including running month
#         months_stayed_in_session = months_stayed
#         bill_amount = calculate_bill_amount(months_stayed_in_session)

#     try:
#         # Update existing bill or create a new one
#         bill = Bill.objects.get(student=allotment_id.student, is_paid=False)
#         print("Found existing bill. Updating amount.")
#         bill.amount = bill_amount
#         bill.save()
#     except Bill.DoesNotExist:
#         # Create a new bill
#         print("Creating a new bill after cancellation.")
#         Bill.objects.create(student=allotment_id.student, amount=bill_amount, months_stayed=months_stayed)

import logging

logger = logging.getLogger(__name__)

def handle_hostel_cancellation(allotment_id):
    logger.debug("handle_hostel_cancellation function is being executed.")
    print(f"Attempting to cancel allotment {allotment_id}")
    current_date = timezone.now().date()
    allotment_date = allotment_id.allotted_date.date()

    # Calculate months stayed
    months_stayed = (current_date.year - allotment_date.year) * 12 + current_date.month - allotment_date.month + 1

    # Determine the session for billing
    session_1_months = [2, 3, 4, 5, 6, 7]
    session_2_months = [8, 9, 10, 11, 12, 1]  # January of next year is represented as 1

    current_month = current_date.month

    # Check which session the current month belongs to
    if current_month in session_1_months:
        session_months = session_1_months  # Set session_months to the first session
    else:
        session_months = session_2_months  # Set session_months to the second session

    # Check if the current session bill is already paid
    current_session_bill = Bill.objects.filter(student=allotment_id.student, months_stayed=months_stayed, is_paid=True).first()

    if not current_session_bill:  # Current session bill is not paid, proceed with billing
        # Check if cancellation month is the same as allotment month
        if current_month == allotment_date.month:
            bill_amount = months_stayed * 1083  # Create a bill for the number of months stayed
        else:
            # Calculate the number of months stayed in the session, including the running month
            months_stayed_in_session = months_stayed
            bill_amount = calculate_bill_amount(months_stayed_in_session)

        try:
            # Update existing bill or create a new one
            bill = Bill.objects.get(student=allotment_id.student, is_paid=False)
            print("Found existing bill. Updating amount.")
            bill.amount = bill_amount
            bill.save()
        except Bill.DoesNotExist:
            # Create a new bill
            print("Creating a new bill after cancellation.")
            Bill.objects.create(student=allotment_id.student, amount=bill_amount, months_stayed=months_stayed)
    else:
        print("Current session bill is already paid. Skipping handle_hostel_cancellation.")


def handle_hostel_allotment(student):
    generate_hostel_bill(student, 6)  # Allotment, so create a 6-month bill


#/working/ import logging

# logger = logging.getLogger(__name__)

# def handle_hostel_cancellation(allotment_id):
#     logger.debug("handle_hostel_cancellation function is being executed.")
#     print(f"Attempting to cancel allotment {allotment_id}")
#     current_date = timezone.now().date()
#     allotment_date = allotment_id.allotted_date.date()

#     # Calculate months stayed
#     months_stayed = (current_date.year - allotment_date.year) * 12 + current_date.month - allotment_date.month + 1

#     # Determine the session for billing
#     session_1_months = [2, 3, 4, 5, 6, 7]
#     session_2_months = [8, 9, 10, 11, 12, 1]  # January of next year is represented as 1

#     current_month = current_date.month

#     # Check which session the current month belongs to
#     if current_month in session_1_months:
#         session_months = session_1_months  # Set session_months to the first session
#     else:
#         session_months = session_2_months  # Set session_months to the second session

#     # Check if cancellation month is the same as allotment month
#     if current_month == allotment_date.month:
#         bill_amount = 1083  # Create a bill for one month
#     else:
#         # Calculate the number of months stayed in the session, including running month
#         months_stayed_in_session = months_stayed
#         bill_amount = calculate_bill_amount(months_stayed_in_session)

#     try:
#         # Update existing bill or create a new one
#         bill = Bill.objects.get(student=allotment_id.student, is_paid=False)
#         print("Found existing bill. Updating amount.")
#         bill.amount = bill_amount
#         bill.save()
#     except Bill.DoesNotExist:
#         # Create a new bill
#         print("Creating a new bill after cancellation.")
#         Bill.objects.create(student=allotment_id.student, amount=bill_amount, months_stayed=months_stayed)





# def bill_detail(request, pk):
#     bill = get_object_or_404(Bill, pk=pk)
#     context = {'bill': bill}
#     return render(request, 'bill_detail.html', context)

from django.shortcuts import render, get_object_or_404

def bill_detail(request, pk):
    bill = get_object_or_404(Bill, pk=pk)

    # Ensure that the associated HostelAllotmentRegistration is not None
    if bill.student:
        try:
            hostel_allotment = HostelAllotmentRegistration.objects.get(student=bill.student)
            full_name = hostel_allotment.full_name
            father_name = hostel_allotment.father_name
            course = hostel_allotment.course
        except HostelAllotmentRegistration.DoesNotExist:
            # Handle the case where HostelAllotmentRegistration is not available
            full_name = "N/A"
            father_name = "N/A"
            course = "N/A"
    else:
        # Handle the case where the bill does not have a student associated
        full_name = "N/A"
        father_name = "N/A"
        course = "N/A"

    context = {
        'bill': bill,
        'full_name': full_name,
        'father_name': father_name,
        'course': course,
    }

    return render(request, 'bill_detail.html', context)


from django.shortcuts import render
from django.utils import timezone
from .models import MessPayment, HostelAllotmentRegistration
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from .models import MessPayment
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta
from django.utils import timezone

def mess_payments(request):
    user = request.user

    # Check if the student has a hostel allotment
    has_hostel_allotment = HostelAllotmentRegistration.objects.filter(student=user).exists()

    if has_hostel_allotment:
        # Check if there is a mess payment record for the current month
        current_date = timezone.now()
        current_month_start = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Initialize last_billing_date as None
        last_billing_date = None
        
        # Find the last billing date if it exists
        last_billing_record = MessPayment.objects.filter(student=user).order_by('-generated_date').first()
        
        if last_billing_record:
            last_billing_date = last_billing_record.generated_date
        
        # Check if the last billing date is before the start of the current month
        if not last_billing_date or last_billing_date < current_month_start:
            # Check if a bill for the current month already exists
            current_month_record = MessPayment.objects.filter(student=user, months_name=current_date.strftime("%B %Y")).first()
            if not current_month_record:
                # Calculate the day of the month when the student allots a hostel
                allotment = HostelAllotmentRegistration.objects.filter(student=user, allotted_date__month=current_date.month, allotted_date__year=current_date.year).first()
                allotment_day = allotment.allotted_date.day if allotment else None

                # Calculate the bill amount for the current month based on allotment day
                if allotment_day is not None and allotment_day <= current_date.day:
                    bill_amount = ((current_month_start + timedelta(days=32) - current_date).days + 1) * 85  # Including the current day, assuming 85 INR per day
                else:
                    if allotment_day is not None:
                        # If allotment_day is available, calculate bill accordingly
                        bill_amount = ((current_month_start + timedelta(days=32) - current_date).days) * 85 - ((current_month_start + timedelta(days=32)).day - allotment_day + 1) * 85
                    else:
                        # If allotment_day is not available, use a fallback calculation
                        bill_amount = ((current_month_start + timedelta(days=32) - current_date).days) * 85

                MessPayment.objects.create(
                    student=user,
                    months_name=current_date.strftime("%B %Y"),
                    amount=bill_amount,
                    generated_date=current_date,
                    status=False  # Initially unpaid
                )

    # Retrieve all mess payment records for the student
    mess_records = MessPayment.objects.filter(student=user)

    context = {'mess_records': mess_records}
    return render(request, 'mess_payments.html', context)




# def mess_payments(request):
#     user = request.user

#     # Check if the student has a hostel allotment
#     has_hostel_allotment = HostelAllotmentRegistration.objects.filter(student=user).exists()

#     if has_hostel_allotment:
#         # Check if there is a mess payment record for the current month
#         current_date = timezone.now()
#         current_month_start = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
#         current_month_end = (current_month_start + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        
#         # Find the last billing date
#         last_billing_date = current_month_start - timedelta(days=1)
        
#         # Check if the last billing date is before the start of the current month
#         if last_billing_date < current_month_start:
#             # Check if a bill for the current month already exists
#             current_month_record = MessPayment.objects.filter(student=user, months_name=current_date.strftime("%B %Y")).first()
#             if not current_month_record:
#                 # Calculate the bill amount for the current month as per your requirement
#                 bill_amount = ((current_month_end - current_date).days + 1) * 85  # Assuming 85 INR per day

#                 # Check if the user has a hostel allotment for this month
#                 allotment = HostelAllotmentRegistration.objects.filter(student=user, allotted_date__month=current_date.month, allotted_date__year=current_date.year).first()
#                 if allotment and allotment.allotted_date >= current_month_start:
#                     # If the allotment date is in the current month, fix the bill amount for the entire month
#                     bill_amount = 1870  # Fixed bill amount for the starting month

#                 MessPayment.objects.create(
#                     student=user,
#                     months_name=current_date.strftime("%B %Y"),
#                     amount=bill_amount,
#                     generated_date=current_date,
#                     status=False  # Initially unpaid
#                 )

#                 # Update the last billing date
#                 last_billing_date = current_month_end

#         # Calculate the start of the next month
#         next_month_start = (current_month_end + timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
#         # Check if it's a new month
#         if current_date >= next_month_start:
#             # Check if a bill for the next month already exists
#             next_month_record = MessPayment.objects.filter(student=user, months_name=next_month_start.strftime("%B %Y")).first()
#             if not next_month_record:
#                 # Generate a full bill for the next month
#                 next_month_end = (next_month_start + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
                
#                 # Calculate the bill amount for the next month as per your requirement
#                 bill_amount = (next_month_end - next_month_start).days * 85  # Assuming 85 INR per day

#                 MessPayment.objects.create(
#                     student=user,
#                     months_name=next_month_start.strftime("%B %Y"),
#                     amount=bill_amount,
#                     generated_date=next_month_start,
#                     status=False  # Initially unpaid
#                 )

#                 # Update the last billing date
#                 last_billing_date = next_month_end

#     # Retrieve all mess payment records for the student
#     mess_records = MessPayment.objects.filter(student=user)

#     context = {'mess_records': mess_records}
#     return render(request, 'mess_payments.html', context)



# def mess_bill_details(request, mess_payment_id):
#     # Retrieve the mess bill record using the provided ID
#     mess_payment = get_object_or_404(MessPayment, id=mess_payment_id)

#     context = {'mess_payment': mess_payment}
#     return render(request, 'mess_bill_details.html', context)

from django.shortcuts import render, get_object_or_404

def mess_bill_details(request, mess_payment_id):
    mess_payment = get_object_or_404(MessPayment, id=mess_payment_id)

    # Ensure that the associated HostelAllotmentRegistration is not None
    if mess_payment.student:
        try:
            hostel_allotment = HostelAllotmentRegistration.objects.get(student=mess_payment.student)
            full_name = hostel_allotment.full_name
        except HostelAllotmentRegistration.DoesNotExist:
            # Handle the case where HostelAllotmentRegistration is not available
            full_name = "N/A"
    else:
        # Handle the case where the mess_payment does not have a student associated
        full_name = "N/A"

    context = {
        'mess_payment': mess_payment,
        'full_name': full_name,
    }

    return render(request, 'mess_bill_details.html', context)


def download_mess_bill(request, mess_payment_id):
    # Retrieve the MessPayment instance
    mess_payment = get_object_or_404(MessPayment, id=mess_payment_id)

    # Generate the bill content (you can use a template)
    bill_content = render_to_string('mess_bill_details.html', {'mess_payment': mess_payment})

    # Create an HTTP response with the bill content as a PDF file
    response = HttpResponse(bill_content, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="mess_bill_{timezone.now()}.pdf"'

    return response


from .models import Notification
from .forms import NotificationForm

def send_notification(request):
    if request.method == 'POST':
        form = NotificationForm(request.POST, request.FILES)
        if form.is_valid():
            notification = form.save(commit=False)
            # Set the filename for the attachment based on the title
            if notification.attachment:
                file_extension = notification.attachment.name.split('.')[-1]
                filename = f"{notification.title}.{file_extension}"
                notification.attachment.name = filename
            notification.save()
            # Notify users here (implementing notifications is more complex).
            return redirect('home')  # Redirect to the home page after sending.
    else:
        form = NotificationForm()
    return render(request, 'send_notification.html', {'form': form})


def view_notifications(request):
    notifications = Notification.objects.all().order_by('-created_at')
    return render(request, 'notifications.html', {'notifications': notifications})


def notification_detail(request, notification_id):
    notification = get_object_or_404(Notification, pk=notification_id)
    return render(request, 'notification_detail.html', {'notification': notification})



# views.py

from django.shortcuts import render, redirect
from django.contrib import messages
# from .models import Attendance
from datetime import date
from django.contrib.auth.decorators import user_passes_test
from .models import CustomUser, HostelAllotmentRegistration
from django.forms import formset_factory
from .forms import TakeAttendanceForm, AttendanceRecordForm  # Import the AttendanceRecordForm
from django.db import transaction
from .models import DailyAttendance, AttendanceRecord 
from django.contrib import messages

# def take_attendance(request):
#     if not request.user.is_staff:
#         return redirect('home')  # Redirect non-admin users

#     # Retrieve students with hostel allotment and get their full names, registration numbers
#     allotment_students = HostelAllotmentRegistration.objects.filter(student__is_active=True)
#     student_data = [(student.registration_number, student.full_name) for student in allotment_students]

#     today = date.today()
    
#     if request.method == 'POST':
#         selected_date = request.POST.get('attendance_date')

#         # Check if attendance already exists for the selected date
#         if DailyAttendance.objects.filter(date=selected_date).exists():
#             messages.error(request, 'Attendance for the selected date has already been recorded.')
#             return redirect('take_attendance')

#         # Check if the 'confirm_checkbox' field is present in the request
#         is_confirmed = 'confirm_checkbox' in request.POST

#         # Create a DailyAttendance record for the selected date
#         daily_attendance, created = DailyAttendance.objects.get_or_create(date=selected_date)

#         try:
#             with transaction.atomic():
#                 # Iterate through the student data and save attendance records
#                 for reg_number, full_name in student_data:
#                     is_present = request.POST.get('student_present_' + reg_number) == 'on'

#                     # Get the student based on registration number
#                     student = CustomUser.objects.get(registration_number=reg_number)

#                     # Create or update the AttendanceRecord for the student and date
#                     attendance_record, created = AttendanceRecord.objects.get_or_create(
#                         student=student,
#                         attendance=daily_attendance
#                     )
#                     attendance_record.is_present = is_present
#                     attendance_record.save()

#             messages.success(request, 'Attendance has been recorded successfully.')

#             if is_confirmed:
#                 return redirect('upload_attendance')
#         except Exception as e:
#             messages.error(request, f'Error: {str(e)}')

#     context = {
#         'today': today,
#         'student_data': student_data,  # Include student_data in the context
#     }
#     return render(request, 'attendance/take_attendance.html', context)



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import HostelAllotmentRegistration, DailyAttendance, AttendanceRecord
from datetime import date
from django.db import transaction
from .models import CustomUser  # Assuming you have a 'CustomUser' model
from django.urls import reverse
from django.core.mail import send_mail
from django.http import JsonResponse

from django.db import transaction

import json

# def take_attendance(request):
#     if not request.user.is_staff:
#         return redirect('home')  # Redirect non-admin users

#     # Retrieve students with hostel allotment and get their full names, registration numbers
#     allotment_students = HostelAllotmentRegistration.objects.filter(student__is_active=True)
#     student_data = [(student.registration_number, student.full_name) for student in allotment_students]

#     today = date.today()
    
#     if request.method == 'POST':
#         selected_date = request.POST.get('attendance_date')

#         # Check if attendance already exists for the selected date
#         if DailyAttendance.objects.filter(date=selected_date).exists():
#             messages.error(request, 'Attendance for the selected date has already been recorded.')
#             return redirect('take_attendance')

#         # Check if the 'confirm_checkbox' field is present in the request
#         is_confirmed = 'confirm_checkbox' in request.POST

#         # Create a DailyAttendance record for the selected date
#         daily_attendance, created = DailyAttendance.objects.get_or_create(date=selected_date)

#         try:
#             with transaction.atomic():
#                 # Iterate through the student data and save attendance records
#                 for reg_number, full_name in student_data:
#                     checkbox_key = 'student_present_' + reg_number
#                     is_present = checkbox_key in request.POST and request.POST.get(checkbox_key) == 'on'

#                     # Get the student based on registration number
#                     student = CustomUser.objects.get(registration_number=reg_number)

#                     # Create or update the AttendanceRecord for the student and date
#                     attendance_record, created = AttendanceRecord.objects.get_or_create(
#                         student=student,
#                         attendance=daily_attendance
#                     )
#                     attendance_record.is_present = is_present
#                     attendance_record.save()

#             messages.success(request, 'Attendance has been recorded successfully.')

#             if is_confirmed:
#                 return redirect('take_attendance')
#         except Exception as e:
#             messages.error(request, f'Error: {str(e)}')

#     context = {
#         'today': today,
#         'student_data': student_data,  # Include student_data in the context
#     }
#     return render(request, 'attendance/take_attendance.html', context)

# views.py
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import HostelAllotmentRegistration, AttendanceRecord
from datetime import date
from django.db import transaction
from .models import CustomUser
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def take_attendance(request):
    if not request.user.is_authenticated:
        return redirect('login')

    # Check if the user is a staff member
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to take attendance.')
        return redirect('home')

    if request.method == 'POST':
        selected_hostel_id = request.POST.get('selectedHostelId')
        selected_date = request.POST.get('attendanceDate')

        if not selected_hostel_id:
            messages.error(request, 'Please select a hostel.')
            return redirect('take_attendance')

        # Check if attendance records already exist for the selected date and hostel
        existing_records = AttendanceRecord.objects.filter(
            student__hostelallotmentregistration__allotted_hostel_id=selected_hostel_id,
            attendance__date=selected_date,
        )

        if existing_records.exists():
            messages.error(request, f'Attendance for {selected_date} in this hostel has already been taken.')
            return redirect('take_attendance')

        students = HostelAllotmentRegistration.objects.filter(allotted_hostel_id=selected_hostel_id)

        try:
            with transaction.atomic():
                for student in students:
                    for floor in range(1, student.allotted_room.floor_number + 1):
                        checkbox_id = f'student_present_{student.registration_number}_floor_{floor}'
                        is_present = checkbox_id in request.POST
                        AttendanceRecord.objects.create(
                            student=student,
                            floor=floor,
                            date=selected_date,
                            is_present=is_present
                        )

        except Exception as e:
            messages.error(request, f'Error saving attendance: {str(e)}')
            return redirect('take_attendance')

        messages.success(request, 'Attendance has been recorded successfully.')
        return redirect('take_attendance')

    hostels = HostelAllotmentRegistration.objects.all().values('allotted_hostel__id', 'allotted_hostel__name').distinct()
    return render(request, 'attendance/take_attendance.html', {'hostels': hostels})




import json
from django.http import JsonResponse
from django.db import transaction
from .models import DailyAttendance, AttendanceRecord, HostelAllotmentRegistration, CustomUser


#// @csrf_exempt
# def save_attendance(request):
#     print("save view is called")
    
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body.decode('utf-8'))
#             print("data")
#             print(data)

#             selectedHostelId = data.get('selectedHostelId')
#             print("selectedHostelId")
#             print(selectedHostelId)
#             selectedDate = data.get('attendanceDate')
#             print("selectedDate")
#             print(selectedDate)
#             checkboxStates = data.get('checkboxStates')
#             print("checkboxStates")
#             print(checkboxStates)

#             if not selectedHostelId or not selectedDate or not checkboxStates:
#                 return JsonResponse({'error': 'Invalid or missing data in the request.'}, status=400)

#             try:
#                 # Get the available floors for the selected hostel
#                 selectedHostel = Hostel.objects.get(pk=selectedHostelId)
#                 available_floors = list(HostelRoom.objects.filter(hostel=selectedHostel).values_list('floor_number', flat=True).distinct())

#                 print("available_floors")
#                 print(available_floors)

#                 if not available_floors:
#                     return JsonResponse({'error': 'No floors available for the specified hostel.'}, status=400)

#                 allotment_students = HostelAllotmentRegistration.objects.filter(
#                     allotted_hostel_id=selectedHostelId,
#                     allotted_room__floor_number__in=available_floors
#                 )

#                 print("allotment_students")
#                 print(allotment_students)

#                 # Check if there are students allocated to the specified hostel
#                 if not allotment_students:
#                     return JsonResponse({'error': 'No students allocated to the specified hostel.'}, status=400)

#                 print("daily_attendance is called")

#                 try:
#                     daily_attendance, created = DailyAttendance.objects.get_or_create(date=selectedDate, hostel=selectedHostel)
#                     print("daily_attendance")
#                     print(daily_attendance)
#                     print("created:", created)

#                     if not created:
#                         print("DailyAttendance object already exists.")

#                     with transaction.atomic():
#                         for student in allotment_students:
#                             print("Processing student:", student)
#                             reg_number = student.registration_number
#                             full_name = student.full_name   # Retrieve full_name from associated CustomUser
#                             print(full_name)
#                             floor_number = student.allotted_room.floor_number
#                             checkbox_key = f'student_present_{reg_number}_floor_{floor_number}'
#                             # Check if the checkbox is marked true
#                             is_present = any(entry['registration_number'] == reg_number and entry['present'] for entry in checkboxStates)

#                             attendance_record, created = AttendanceRecord.objects.get_or_create(
#                                 student=student,
#                                 attendance=daily_attendance
#                             )
#                             print("attendance_record")
#                             print(attendance_record)
#                             attendance_record.is_present = is_present
#                             attendance_record.save()
#                             print("Attendance record saved successfully.")

#                     return JsonResponse({'success': 'Attendance saved successfully'})
#                 except Exception as e:
#                     print(f"Error creating/retrieving DailyAttendance or saving attendance: {str(e)}")
#                     return JsonResponse({'error': f'Error saving attendance: {str(e)}'}, status=500)
#             except Exception as e:
#                 print(f"Error getting available floors: {str(e)}")
#                 return JsonResponse({'error': f'Error getting available floors: {str(e)}'}, status=500)
#         except Exception as e:
#             print(f"Error parsing request data: {str(e)}")
#             return JsonResponse({'error': f'Error parsing request data: {str(e)}'}, status=400)
#     else:
#         return JsonResponse({'error': 'Invalid request method'}, status=400)


from django.contrib import messages

# @csrf_exempt
# def save_attendance(request):
#     print("save view is called")
    
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body.decode('utf-8'))
#             print("data")
#             print(data)

#             selectedHostelId = data.get('selectedHostelId')
#             print("selectedHostelId")
#             print(selectedHostelId)
#             selectedDate = data.get('attendanceDate')
#             print("selectedDate")
#             print(selectedDate)
#             checkboxStates = data.get('checkboxStates')
#             print("checkboxStates")
#             print(checkboxStates)

#             if not selectedHostelId or not selectedDate or not checkboxStates:
#                 return JsonResponse({'error': 'Invalid or missing data in the request.'}, status=400)

#             try:
#                 # Get the selected hostel
#                 selectedHostel = Hostel.objects.get(pk=selectedHostelId)

#                 # Check if a DailyAttendance record already exists for the specified date and hostel
#                 existing_record = DailyAttendance.objects.filter(date=selectedDate, hostel=selectedHostel).first()

#                 if existing_record:
#                     # Record already exists, you may want to handle this case based on your requirement
#                     return JsonResponse({'error': f'Record for {selectedDate} and {selectedHostel.name} already exists.'}, status=400)

#                 print("daily_attendance is called")

#                 # Retrieve allotment students for the specified hostel and floors
#                 available_floors = list(HostelRoom.objects.filter(hostel=selectedHostel).values_list('floor_number', flat=True).distinct())
#                 allotment_students = HostelAllotmentRegistration.objects.filter(
#                     allotted_hostel_id=selectedHostelId,
#                     allotted_room__floor_number__in=available_floors
#                 )

#                 if not allotment_students:
#                     return JsonResponse({'error': 'No students allocated to the specified hostel.'}, status=400)

#                 try:
#                     # Create a new DailyAttendance record
#                     daily_attendance, created = DailyAttendance.objects.get_or_create(date=selectedDate, hostel=selectedHostel)
#                     print("daily_attendance")
#                     print(daily_attendance)
#                     print("created:", created)

#                     if not created:
#                         print("DailyAttendance object already exists.")

#                     with transaction.atomic():
#                         for student in allotment_students:
#                             print("Processing student:", student)
#                             reg_number = student.registration_number
#                             full_name = student.full_name   # Retrieve full_name from associated CustomUser
#                             print(full_name)
#                             floor_number = student.allotted_room.floor_number
#                             checkbox_key = f'student_present_{reg_number}_floor_{floor_number}'
#                             # Check if the checkbox is marked true
#                             is_present = any(entry['registration_number'] == reg_number and entry['present'] for entry in checkboxStates)

#                             attendance_record, created = AttendanceRecord.objects.get_or_create(
#                                 student=student,
#                                 attendance=daily_attendance
#                             )
#                             print("attendance_record")
#                             print(attendance_record)
#                             attendance_record.is_present = is_present
#                             attendance_record.save()
#                             print("Attendance record saved successfully.")

#                     # Add success message
#                     messages.success(request, 'Attendance has been recorded successfully.')

#                     return JsonResponse({'success': 'Attendance saved successfully'})
#                 except Exception as e:
#                     print(f"Error creating/retrieving DailyAttendance or saving attendance: {str(e)}")
#                     return JsonResponse({'error': f'Error saving attendance: {str(e)}'}, status=500)
#             except Exception as e:
#                 print(f"Error getting available floors: {str(e)}")
#                 return JsonResponse({'error': f'Error getting available floors: {str(e)}'}, status=500)
#         except Exception as e:
#             print(f"Error parsing request data: {str(e)}")
#             return JsonResponse({'error': f'Error parsing request data: {str(e)}'}, status=400)
#     else:
#         return JsonResponse({'error': 'Invalid request method'}, status=400)


from django.db import transaction

@csrf_exempt
def save_attendance(request):
    print("save view is called")
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            print("data")
            print(data)

            selectedHostelId = data.get('selectedHostelId')
            print("selectedHostelId")
            print(selectedHostelId)
            selectedDate = data.get('attendanceDate')
            print("selectedDate")
            print(selectedDate)
            checkboxStates = data.get('checkboxStates')
            print("checkboxStates")
            print(checkboxStates)

            if not selectedHostelId or not selectedDate or not checkboxStates:
                return JsonResponse({'error': 'Invalid or missing data in the request.'}, status=400)

            try:
                # Get the selected hostel
                selectedHostel = Hostel.objects.get(pk=selectedHostelId)

                # Check if a DailyAttendance record already exists for the specified date and hostel
                existing_record = DailyAttendance.objects.filter(date=selectedDate, hostel=selectedHostel).first()

                if existing_record:
                    # Record already exists, return an error message
                    messages.error(request, f'Record for {selectedDate} and {selectedHostel.name} already exists.')
                    return JsonResponse({'error': f'Record for {selectedDate} and {selectedHostel.name} already exists.'}, status=400)

                print("daily_attendance is called")

                # Retrieve allotment students for the specified hostel and floors
                available_floors = list(HostelRoom.objects.filter(hostel=selectedHostel).values_list('floor_number', flat=True).distinct())
                allotment_students = HostelAllotmentRegistration.objects.filter(
                    allotted_hostel_id=selectedHostelId,
                    allotted_room__floor_number__in=available_floors
                )

                if not allotment_students:
                    return JsonResponse({'error': 'No students allocated to the specified hostel.'}, status=400)

                try:
                    # Create a new DailyAttendance record
                    daily_attendance, created = DailyAttendance.objects.get_or_create(date=selectedDate, hostel=selectedHostel)
                    print("daily_attendance")
                    print(daily_attendance)
                    print("created:", created)

                    if not created:
                        print("DailyAttendance object already exists.")

                    with transaction.atomic():
                        for student in allotment_students:
                            print("Processing student:", student)
                            reg_number = student.registration_number
                            full_name = student.full_name   # Retrieve full_name from associated CustomUser
                            print(full_name)
                            floor_number = student.allotted_room.floor_number
                            checkbox_key = f'student_present_{reg_number}_floor_{floor_number}'
                            # Check if the checkbox is marked true
                            is_present = any(entry['registration_number'] == reg_number and entry['present'] for entry in checkboxStates)

                            attendance_record, created = AttendanceRecord.objects.get_or_create(
                                student=student,
                                attendance=daily_attendance
                            )
                            print("attendance_record")
                            print(attendance_record)
                            attendance_record.is_present = is_present
                            attendance_record.save()
                            print("Attendance record saved successfully.")

                    # Add success message
                    messages.success(request, f'Attendance has been recorded successfully of hostel {selectedHostel.name} of date {selectedDate}.')

                    return JsonResponse({'success': 'Attendance saved successfully'})
                except Exception as e:
                    print(f"Error creating/retrieving DailyAttendance or saving attendance: {str(e)}")
                    return JsonResponse({'error': f'Error saving attendance: {str(e)}'}, status=500)
            except Exception as e:
                print(f"Error getting available floors: {str(e)}")
                return JsonResponse({'error': f'Error getting available floors: {str(e)}'}, status=500)
        except Exception as e:
            print(f"Error parsing request data: {str(e)}")
            return JsonResponse({'error': f'Error parsing request data: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)



from django.http import JsonResponse
from .models import Hostel, HostelRoom

# Import necessary modules
from django.shortcuts import render


def get_available_floors_for_attendance(request, hostel_id):
    try:
        hostel = Hostel.objects.get(pk=hostel_id)
        floors = HostelRoom.objects.filter(hostel=hostel).values_list('floor_number', flat=True).distinct()

        return JsonResponse({'floors': list(floors)})
    except Hostel.DoesNotExist:
        return JsonResponse({'error': 'Hostel not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Your existing views

from django.http import JsonResponse
from .models import HostelAllotmentRegistration, Hostel

def available_students_on_floor(request, hostel_id, floor_number):
    print("available_students_on_floor is called")
    try:
        hostel = Hostel.objects.get(pk=hostel_id)
        rooms_on_floor = HostelAllotmentRegistration.objects.filter(allotted_hostel=hostel, allotted_room__floor_number=floor_number)

        students_on_floor = []
        for registration in rooms_on_floor:
            student = registration
            students_on_floor.append({
                'details': f'Floor {floor_number}, Room {registration.allotted_room.room_number}',
                'registration_number': student.registration_number,
                'full_name': student.full_name,
            })

        print("Students on floor:", students_on_floor)  # Add this print statement

        return JsonResponse({'students': students_on_floor, 'hostel_name': hostel.name, 'floor_name': floor_number})
    except Hostel.DoesNotExist:
        print("Hostel not found")  # Add this print statement
        return JsonResponse({'error': 'Hostel not found'}, status=404)
    except HostelAllotmentRegistration.DoesNotExist:
        print("Allotment registration not found")  # Add this print statement
        return JsonResponse({'error': 'Allotment registration not found'}, status=404)
    except Exception as e:
        print("Error:", str(e))  # Add this print statement
        return JsonResponse({'error': str(e)}, status=500)



def available_floors(request, hostel_id):
    try:
        hostel = Hostel.objects.get(pk=hostel_id)
        floors = HostelRoom.objects.filter(hostel=hostel).values_list('floor_number', flat=True).distinct()

        return JsonResponse({'floors': list(floors)})
    except Hostel.DoesNotExist:
        return JsonResponse({'error': 'Hostel not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def get_available_hostels(request):
    hostels = Hostel.objects.all()
    hostels_data = [{'id': hostel.id, 'name': hostel.name} for hostel in hostels]
    return JsonResponse({'hostels': hostels_data})

from django.http import JsonResponse
from .models import HostelAllotmentRegistration, Hostel

def get_hostel_allotment_info(registration_number):
    try:
        # Fetch allotment information from the existing view
        hostels_data = get_available_hostels(request=None).get('hostels', [])
        
        # Replace this logic with your actual logic to get the allotted hostel based on the registration number
        # Below is just a placeholder; replace it with your actual logic
        allotted_hostel_name = hostels_data[0]['name'] if hostels_data else ''
        
        return {
            'allotted_hostel_name': allotted_hostel_name,
            # Add other fields you want to retrieve
        }
    except Exception as e:
        # Handle exceptions if any
        return {'error': str(e)}


from django.http import JsonResponse
from .models import HostelAllotmentRegistration

def get_students(request):
    hostel_id = request.GET.get('hostel_id')
    
    # Filter students based on the selected hostel
    students = HostelAllotmentRegistration.objects.filter(allotted_hostel_id=hostel_id)
    
    # Include the 'students' key in the response
    data = {'students': [{'id': student.id, 'text': str(student)} for student in students]}
    
    return JsonResponse(data)


def upload_attendance(request):
    if not request.user.is_staff:
        return redirect('home')  # Redirect non-admin users

    return render(request, 'attendance/upload_attendance.html')


from .forms import EditAttendanceForm

# def edit_attendance(request):
#     if not request.user.is_staff:
#         return redirect('home')  # Redirect non-admin users

#     edit_form = EditAttendanceForm(request.POST or None)
#     attendance_records = []  # Initialize an empty list to store attendance records

#     if request.method == 'POST':
#         if edit_form.is_valid():
#             selected_date = edit_form.cleaned_data['attendance_date']
#             # Retrieve all attendance records for the selected date
#             attendance_records = Attendance.objects.filter(date=selected_date)

#     context = {
#         'edit_form': edit_form,
#         'attendance_records': attendance_records,  # Pass the attendance records to the template
#     }
#     return render(request, 'attendance/edit_attendance.html', context)


from django.shortcuts import render, redirect
from django.contrib import messages
from django.forms import formset_factory
from .forms import EditAttendanceForm, AttendanceRecordForm
from .models import DailyAttendance, AttendanceRecord
from datetime import date

def edit_attendance(request):
    if not request.user.is_staff:
        return redirect('home')  # Redirect non-admin users

    if request.method == 'POST':
        edit_form = EditAttendanceForm(request.POST)

        if edit_form.is_valid():
            selected_date = edit_form.cleaned_data['attendance_date']

            try:
                daily_attendance = DailyAttendance.objects.get(date=selected_date)
                attendance_records = AttendanceRecord.objects.filter(attendance=daily_attendance)

                if 'save_button' in request.POST:
                    for record in attendance_records:
                        is_present = request.POST.get(f'student_present_{record.student.registration_number}') == 'on'
                        record.is_present = is_present
                        record.save()

                    messages.success(request, 'Attendance has been edited and saved successfully.')
                    return redirect('take_attendance')
            except DailyAttendance.DoesNotExist:
                messages.error(request, 'Attendance records for the selected date do not exist.')
                return redirect('edit_attendance')
        else:
            messages.error(request, 'The edit form is not valid. Please check the form data.')
    else:
        edit_form = EditAttendanceForm()
        attendance_records = []

    context = {
        'edit_form': edit_form,
        'attendance_records': attendance_records,
    }
    return render(request, 'attendance/edit_attendance.html', context)








    # Add code for editing attendance here

    
from django.shortcuts import render, redirect
from .models import AttendanceRecord
from .forms import ViewAttendanceForm

# def view_attendance(request):
#     student = request.user
#     selected_month = request.GET.get('selected_month')
#     selected_year = request.GET.get('selected_year')

#     # Initialize the form with GET data
#     form = ViewAttendanceForm(request.GET)

#     if selected_month and selected_year:
#         # Filter attendance records for the selected month and year
#         attendance_records = AttendanceRecord.objects.filter(
#             student=student,
#             attendance__date__month=selected_month,
#             attendance__date__year=selected_year
#         )
#     else:
#         attendance_records = []

#     context = {
#         'attendance_records': attendance_records,
#         'form': form,
#         'selected_month': selected_month,
#         'selected_year': selected_year,
#     }
#     return render(request, 'attendance/view_attendance.html', context)

# def view_attendance(request):
#     student = request.user
#     attendances = Attendance.objects.filter(student=student)

#     if request.method == 'POST':
#         selected_month = request.POST.get('selected_month')
#         selected_year = request.POST.get('selected_year')

#         if selected_month and selected_year:
#             # Filter attendances for the selected month and year
#             attendances = attendances.filter(date__month=selected_month, date__year=selected_year)

#     context = {
#         'attendances': attendances,
#     }
#     return render(request, 'attendance/view_attendance.html', context)

# views.py
from django.shortcuts import render
from .models import AttendanceRecord
from .forms import ViewAttendanceForm  # Import your form here

def view_attendance(request):
    print("view_attendance is called")
    student = request.user
    selected_month = request.GET.get('selected_month')
    selected_year = request.GET.get('selected_year')
    

    # Initialize the form with GET data
    form = ViewAttendanceForm(request.GET)

    if selected_month and selected_year:
        # Extract month and year from the selected date
        # Note: You might need to convert the month and year to integers
        selected_month = int(selected_month)
        selected_year = int(selected_year)


        # Filter attendance records for the selected month and year
        attendance_records = AttendanceRecord.objects.filter(
            student__registration_number=student.registration_number,
            attendance__date__month=selected_month,
            attendance__date__year=selected_year
        )

        print("Query:", str(attendance_records.query))
        print("Attendance records count:", attendance_records.count())
        print("attendance_records is called", attendance_records)
    else:
        attendance_records = []

    context = {
        'attendance_records': attendance_records,
        'form': form,
        'selected_month': selected_month,
        'selected_year': selected_year,
    }
    return render(request, 'attendance/view_attendance.html', context)



from django.views import View

class UserProfileView(View):
    def get(self, request, *args, **kwargs):
        # Your view logic here
        return render(request, 'user_profile.html')


# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.base import ContentFile
from .models import CustomUser

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.base import ContentFile
from .models import CustomUser

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser

@csrf_exempt
def save_profile_picture(request):
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        user = request.user
        image_data = request.FILES.get('image_data', None)

        if image_data:
            # Save the profile picture in CustomUser model
            user.profile_picture = image_data
            user.save()

            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error', 'message': 'No file chosen'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@csrf_exempt
def get_profile_picture(request):
    if request.method == 'GET' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        user = request.user
        if user.is_authenticated:
            # Retrieve the profile picture URL
            profile_picture_url = user.profile_picture.url if user.profile_picture else None
            return JsonResponse({'status': 'success', 'profile_picture_url': profile_picture_url})
        else:
            return JsonResponse({'status': 'error', 'message': 'User not authenticated'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})



from django.shortcuts import render, redirect
from .models import MenuItem
from .forms import MenuItemForm

def menu_page(request):
    menu_items = MenuItem.objects.all()
    return render(request, 'menu_page.html', {'menu_items': menu_items})


def edit_menu(request):
    if request.method == 'POST':
        form = MenuItemForm(request.POST, instance=MenuItem.objects.first())
        if form.is_valid():
            form.save()
            return redirect('menu_page')  # Redirect to the menu page after saving
    else:
        form = MenuItemForm(instance=MenuItem.objects.first())
    return render(request, 'menu/edit_menu.html', {'form': form})




from django.contrib import messages
from django.shortcuts import render, redirect
from .models import FeedbackAndComplaint
from django.contrib.auth.decorators import login_required

@login_required
def feedback_complaint_view(request):
    if request.method == 'POST':
        rating = request.POST.get('rating', 0)
        user = request.user
        complaint_text = request.POST.get('complaint-text', '')

        feedback_complaint = FeedbackAndComplaint(user=user, rating=rating, complaint_text=complaint_text)
        feedback_complaint.save()
        messages.success(request, 'Your feedback and complaint have been submitted successfully.')

    return render(request, 'feedback_complaint.html')

import pdfkit
from django.http import HttpResponse
from django.template.loader import get_template
from django.template import Context
from django.conf import settings
from .models import Bill

def generate_pdf(request, bill_id):
    # Get the bill object based on bill_id
    bill = Bill.objects.get(pk=bill_id)

    # Create a PDF using pdfkit
    template = get_template('hotel/templates/bill_details.html')
    context = {'bill': bill}
    html = template.render(context)
    pdf = pdfkit.from_string(html, False, options={'page-size': 'Letter'})

    # Serve the PDF as a download
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="bill_{bill_id}.pdf"'
    return response

from django.shortcuts import render, redirect
from .models import HostelAllotmentRegistration, Bill, MessPayment

from django.shortcuts import render, redirect
from .models import HostelAllotmentRegistration, Bill, MessPayment

def noc_form(request):
    # Check for pending bills
    if Bill.objects.filter(student=request.user, is_paid=False).exists() or MessPayment.objects.filter(student=request.user, status=False).exists():
        messages.error(request, 'You have pending bills of the hostel or mess. Please pay all pending bills first.')
        return redirect('home')

    # Retrieve details from the HostelAllotmentRegistration model
    allotment = HostelAllotmentRegistration.objects.filter(student=request.user, is_canceled=False).first()

    # Check if there is an allotment
    # if allotment is None:
    #     # No allotment found
    #     return render(request, 'noc_form.html', {'hostel_name': None})

    # Pass details to the template for rendering
    context = {
        'hostel_name': allotment.allotted_hostel.name,
        'full_name': allotment.full_name,
        'father_name': allotment.father_name,
        'registration_number': allotment.registration_number,
        'phone': allotment.phone,
        'district': allotment.district,
        'state': allotment.state,
        'department': allotment.department,
        'course': allotment.course,
        'room_number': allotment.allotted_room.room_number,
        # 'cancel_hostel_date': allotment.is_canceled_date,
    }

    # Check for pending bills after canceling the hostel
    if Bill.objects.filter(student=request.user, is_paid=False).exists() or MessPayment.objects.filter(student=request.user, status=False).exists():
        messages.error(request, 'You have pending bills of the hostel or mess. Please pay all pending bills first.')
        return redirect('home')

    return render(request, 'noc_form.html', context)


from django.shortcuts import render

def mess_committee(request):
    return render(request, 'mess_committee.html')






