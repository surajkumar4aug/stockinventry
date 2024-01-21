from rest_framework import serializers
from .models import Address, CustomerDetails,User

class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    address = AddressSerializer()

    class Meta:
        model = User
        fields =  '__all__'
        extra_kwargs = {'password': {'write_only': True}}



class CustomerDetailsSerializer(serializers.ModelSerializer):
    address = AddressSerializer()
    class Meta:
        model = CustomerDetails
        fields = '__all__'
