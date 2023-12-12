# from django.contrib.auth.backends import ModelBackend
# from .models import CustomUser

# class CustomAuthenticationBackend(ModelBackend):
#     def authenticate(self, request, username=None, password=None, **kwargs):
#         try:
#             # First, try to authenticate superuser (admin) based on username
#             user = CustomUser.objects.get(username=username)
#             if user.check_password(password) and user.is_staff:
#                 return user

#             # If superuser authentication fails, try to authenticate regular users based on registration_number
#             user = CustomUser.objects.get(registration_number=username)
#             if user.check_password(password) and user.is_active:
#                 return user
#         except CustomUser.DoesNotExist:
#             # If no user is found, return None to indicate authentication failure
#             return None

from django.contrib.auth.backends import ModelBackend
from .models import CustomUser
from django.db.models import Q

class CustomAuthenticationBackend(ModelBackend):
    def authenticate(self, request, login_identifier=None, password=None, **kwargs):
        try:
            # Check if the provided login_identifier matches the registration number or email
            user = CustomUser.objects.get(Q(registration_number=login_identifier) | Q(email=login_identifier))

            if user.check_password(password) and self.user_can_authenticate(user):
                return user

            return None
        except CustomUser.DoesNotExist:
            # If no user is found, return None to indicate authentication failure
            return None



# from django.contrib.auth import backends
# from django.db.models import Q
# from .models import CustomUser


# class CustomAuthenticationBackend(backends.ModelBackend):
#     def authenticate(self, request, login_identifier=None, password=None, **kwargs):
#         # Check if the user exists in the Register model using their registration number or email
#         user = CustomUser.objects.filter(Q(registration_number=login_identifier) | Q(email=login_identifier)).first()

#         if user is not None and user.check_password(password):
#             return user
#         else:
#             return