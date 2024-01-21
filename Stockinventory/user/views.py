from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated,IsAdminUser,BasePermission
from django.contrib.auth import authenticate, login,logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomerDetailsSerializer, UserSerializer, AddressSerializer
from .models import User,CustomerDetails,Address
import uuid
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.
class UserStaff(BasePermission):
    def has_permission(self, request,view):
        print(request.user)
        return request.user.Staff
class Useradmin(BasePermission):
    def has_permission(self, request,view):
        print(request.user)
        return request.user.admin
class UserSuperAdmin(BasePermission):
    def has_permission(self, request,view):
        return request.user.superadmin    
class fun(APIView):
    permission_classes= [UserStaff]
    def get(self,request):
        ram={"d":"k"}
        return Response({"ram":"jk"})
class signin(APIView):
    def post(self,request):
        email=request.data.get('email')
        password=request.data.get('password')
        print(email,password)
        user= authenticate(email=email,password=password)
        print(user)
        if user is not None:
            login(request,user)  
            
            return Response({'goof':"jnhsd"}) 
        else:
            return Response({"ram":"uu"})
def log(request) :
    logout(request)    
    return Response({"ta":"y"})   

# class staffregister(APIView):
#     def post(self,request):
#         email=request.data.get('email')
#         password=request.data.get('password')
#         name=request.data.get("name")
#         phone=request.data.get("phone")
#         user_=request.data.get("user")
#         try:
#             if user_ =='staff':
#                 us=User.objects.create_staffuser(name, email, phone, password)
#             elif user_ =='admin':
#                 us=User.objects.create_superuser(name, email, phone, password)    
#             return Response({"message":"successesd"})
#         except:
#             return Response({"message":"something wrong"})


# from rest_framework import status
# from .serializers import CustomerDetailsSerializer

# class CustomerRegister(APIView):
#     permission_classes= [UserAdmin]
#     def post(self, request):
#         serializer = CustomerDetailsSerializer(data=request.data)
#         if serializer.is_valid():
#             address_data = serializer.validated_data.pop('address')
#             address = Address.objects.create(**address_data)
#             customer = CustomerDetails.objects.create(address=address, **serializer.validated_data)
#             return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#     def get(self, request):
#         customer = CustomerDetails.objects.all()
#         serializer = CustomerDetailsSerializer(customer)
#         return Response({'data': serializer.data}, status=status.HTTP_200_OK)



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, AddressSerializer

class RegisterStaffAdminAPI(APIView):
    #permission_classes = [UserSuperAdmin]

    def post(self, request):
        try:
            user_id = User.objects.last()
            if user_id:
                user_id = user_id.id + 1
            else:
                user_id = user_id.id

            request.data['staff_id'] = user_id
            user_serializer = UserSerializer(data=request.data)
            address_serializer = AddressSerializer(data=request.data['address'])
            print(user_serializer.is_valid(), address_serializer.is_valid())
            print()

            if user_serializer.is_valid() and address_serializer.is_valid():
                user_data = user_serializer.validated_data
                address_data = address_serializer.validated_data
                print(user_serializer.data)
                full_name = user_data.get('full_name')
                email = user_data.get('email')
                phone = user_data.get('phone')
                password = user_data.get('password')
                id_proof = user_data.get('id_proof')
                is_staff = user_data.get('staff')
                is_admin = user_data.get('admin', False)
                is_superadmin = user_data.get('superadmin', False)

                if not is_superadmin and not is_admin and is_staff:
                    staff_id = "SID_06" + str(user_id)  # Generate a unique ID for staff
                    user = User.objects.create_user(full_name=full_name, email=email, phone=phone, password=password, address=address_data, staff_id=staff_id, id_proof=id_proof)
                elif not is_admin and is_staff:
                    staff_id = "SID_06" + str(user_id)  # Generate a unique ID for staff
                    user = User.objects.create_staffuser(full_name=full_name, email=email, phone=phone, password=password, address=address_data, staff_id=staff_id, id_proof=id_proof)
                elif is_superadmin:
                    staff_id = "SID_06" + str(user_id)  # Generate a unique ID for admin
                    user = User.objects.create_superuser(full_name=full_name, email=email, phone=phone, password=password, address=address_data, staff_id=staff_id, id_proof=id_proof)
                else:
                    return Response({'message': 'Invalid user role'}, status=status.HTTP_400_BAD_REQUEST)

                refresh = RefreshToken.for_user(user)
                response_data = {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'message': 'Registration successful'
                }

                return Response(response_data, status=status.HTTP_201_CREATED)

            return Response({'message': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomerDetails
from .serializers import CustomerDetailsSerializer, AddressSerializer

class Customer(APIView):
    permission_classes = [UserStaff]

    def get(self, request):
        try:
            queryset = CustomerDetails.objects.all()
            name = self.request.query_params.get('name')
            customer_id = self.request.query_params.get('customer_id')

            if name:
                queryset = queryset.filter(name__icontains=name)

            if customer_id:
                queryset = queryset.filter(customer_id=customer_id)

            serializer = CustomerDetailsSerializer(queryset, many=True)
            return Response(serializer.data)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            customer = CustomerDetails.objects.last()
            if customer:
                request.data["customer_id"] = "CID_01" + str(customer.id + 1)
            else:
                request.data["customer_id"] = "CID_01" + str(1)

            address_data = request.data['address']
            address_serializer = AddressSerializer(data=address_data)
            if address_serializer.is_valid():
                address = address_serializer.save()
                serializer = CustomerDetailsSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save(address=address)
                    return Response(serializer.data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        try:
            customer_id = request.data.get('customer_id')
            try:
                customer = CustomerDetails.objects.get(customer_id=customer_id)
            except CustomerDetails.DoesNotExist:
                return Response({"detail": "Customer does not exist."}, status=status.HTTP_404_NOT_FOUND)

            address_data = request.data.pop('address')
            address_serializer = AddressSerializer(customer.address, data=address_data)
            if address_serializer.is_valid():
                address = address_serializer.save()
                serializer = CustomerDetailsSerializer(customer, data=request.data)
                if serializer.is_valid():
                    serializer.save(address=address)
                    return Response(serializer.data)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request):
        try:
            customer_id = request.data.get('customer_id')
            try:
                customer = CustomerDetails.objects.get(customer_id=customer_id)
            except CustomerDetails.DoesNotExist:
                return Response({"detail": "Customer does not exist."}, status=status.HTTP_404_NOT_FOUND)

            customer.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
#from django.utils.encoding import force_bytes, force_text
from django.conf import settings

#from templated_mail.mail import BaseEmailMessage
from rest_framework_simplejwt.authentication import JWTAuthentication

class LoginAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    def post(self, request):
        # Retrieve email and password from the request data
        email = request.data.get('email')
        password = request.data.get('password')

        # Perform authentication
        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
        else:
            return Response({'error': 'Invalid credentials'}, status=400)


class LogoutAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # Blacklist the refresh token to invalidate it
        refresh_token = request.data.get('refresh_token')
        print(RefreshToken(refresh_token).blacklist())
        return Response({'message': 'Logged out successfully'})
        
class refreshtoken(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # Blacklist the refresh token to invalidate it
        refresh_token = request.data.get('refresh_token')
        refresh=RefreshToken(refresh_token)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

# class ForgotPasswordEmail(BaseEmailMessage):
#     template_name = 'forgot_password_email.html'


# class ForgotPasswordAPIView(APIView):
#     def post(self, request):
#         # Retrieve email from the request data
#         email = request.data.get('email')

#         # Check if the email is associated with a user
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({'error': 'No user found with this email'}, status=400)

#         # Generate a token for password reset
#         token = user.generate_reset_token()

#         # Send the password reset email
#         current_site = get_current_site(request)
#         email_subject = 'Password Reset'
#         email_message = render_to_string('forgot_password_email.html', {
#             'user': user,
#             'domain': current_site.domain,
#             'token': token,
#         })
#         print(email_message)
#         send_mail(email_subject, email_message, settings.DEFAULT_FROM_EMAIL, [email])

#         return Response({'message': 'Password reset email sent'})


class ResetPasswordAPIView(APIView):
    def post(self, request, token):
        # Decode the token
        try:
            uid = force_text(urlsafe_base64_decode(token))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid token'}, status=400)

        # Retrieve the new password from the request data
        new_password = request.data.get('new_password')

        # Set the new password for the user
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successfully'})

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Your logic to fetch and process the data
        data = {
            'message': f'Hello, {user.email}! This is protected data.'
        }
        return Response(data)


