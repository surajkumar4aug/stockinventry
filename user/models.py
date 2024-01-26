# from django.db import models

# from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError('The Email field must be set')
        
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save()
#         return user
    
#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         return self.create_user(email, password, **extra_fields)

# class User(AbstractBaseUser):
#     email = models.EmailField(unique=True)
#     first_name = models.CharField(max_length=100)
#     last_name = models.CharField(max_length=100)
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
    
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['first_name', 'last_name']
    
#     objects = CustomUserManager()

#     def __str__(self):
#         return self.email

# class Admin(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
#     department = models.CharField(max_length=100)
#     # Add other admin-specific fields as needed
    
#     def __str__(self):
#         return self.user.email
import re

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, full_name, email, phone, password,address, staff_id, id_proof,  is_active=True, is_staff=True, is_admin=False, is_superadmin=False):
        if not email:
            raise ValueError('Users Must Have A Email')
        if not full_name:
            raise ValueError('Users Must Have A Full Name')
        if not phone:
            raise ValueError('Users Must Have A Phone Number')
        if not password:
            raise ValueError('Users Must Have A Password')

        if re.fullmatch('^[a-z0-9.]+@[a-z0-9]+.[a-z]{2,}$', email.lower()) is None:
            raise ValueError('Invalid Email Address')

        if re.fullmatch('^[a-z0-9.@#$%^&*-+~!]{8,}$', password.lower()) is None:
            raise ValueError('Password Must Be At Least 8 Characters')

        user_obj = self.model(
            email=self.normalize_email(email)
        )
        if address is None:
        # Set a default address when it is not provided
            address = {
                'area': 'Naya Tola Bihari',
                'district': 'Jamui',
                'state': 'Bihar',
                'pincode': 811307
            }
        print(address)
        user_address = Address.objects.create(
            area=address['area'],
            district=address['district'],
            state=address['state'],
            pincode=address['pincode']
        )

        user_obj.address = user_address
        user_obj.full_name = full_name
        user_obj.phone = phone
        user_obj.active = is_active
        user_obj.staff_id= staff_id
        user_obj.id_proof= id_proof
        user_obj.staff = is_staff
        user_obj.admin = is_admin
        user_obj.superadmin = is_superadmin
        user_obj.set_password(password)
        user_obj.save(using=self._db)

        return user_obj

    def create_adminuser(self, full_name, email, phone, password, address, staff_id,id_proof ):
        user = self.create_user(full_name=full_name, email=email, phone=phone, password=password, 
                                address=address, staff_id=staff_id, id_proof=id_proof, is_admin=True)
        return user

    # def create_superuser(self, full_name, email, phone, password, address, staff_id=None,id_proof=None):
    #     user = self.create_user(full_name=full_name, email=email, phone=phone, password=password, 
    #                             address=address, staff_id=staff_id, id_proof=id_proof, is_staff=True, is_admin=True)
    #     return user
    def create_superuser(self, full_name, email, phone, password, address=None, staff_id=None, id_proof=None):
        if staff_id is None: 
            user_id = User.objects.last()
            if user_id:
                staff_id = "SID_06"+str(user_id.id+1)
            else:
                staff_id = "SID_06"+str(user_id.id)    
        user = self.create_user(full_name=full_name, email=email, phone=phone, password=password, 
                            address=address, staff_id=staff_id, id_proof=id_proof, is_admin=True, is_superadmin=True)
        return user
class Address(models.Model):
    area=models.CharField(max_length=100)
    district=models.CharField(max_length=50)
    state=models.CharField(max_length=25)
    pincode=models.IntegerField(max_length=6)
    def __str__(self):
        return str(self.state)
class User(AbstractBaseUser):
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, max_length=255,verbose_name='Email')
    phone = models.CharField(max_length=11)
    staff_id=models.CharField(unique=True,max_length=25)
    id_proof=models.CharField(null=True,max_length=11)
    address=models.ForeignKey(Address,null=True, blank=True, on_delete=models.CASCADE)
    active = models.BooleanField(default=True)  # can login
    staff = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)  # staff User
    superadmin = models.BooleanField(default=False)  # superuser

    objects = UserManager()

    USERNAME_FIELD = 'email'
    # Username Field and password fields are required by default
    REQUIRED_FIELDS = ['full_name', 'phone']

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.full_name

    def get_short_name(self):
        return self.full_name.split(' ')[0].capitalize()

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_active(self):
        return self.active

    @property
    def is_staff(self):
        return self.admin

    @property
    def is_admin(self):
        return self.superuser


class CustomerDetails(models.Model):
    name=models.CharField(max_length=25)
    customer_id=models.CharField(max_length=25)
    shop_name=models.CharField(max_length=25)
    mob_no=models.IntegerField(max_length=10)
    gst_no=models.CharField(max_length=20,null=True)
    address=models.ForeignKey(Address,on_delete=models.CASCADE)
    

