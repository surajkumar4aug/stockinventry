from django.db import models

# Create your models here.
class Products(models.Model):
    name = models.CharField(max_length=30)
    product_id = models.CharField(unique=True, max_length=30)
    quantity=models.IntegerField()
    weight=models.IntegerField()
    mrp=models.DecimalField(max_digits=5,decimal_places=2)
    price = models.DecimalField(max_digits=5,decimal_places=2)
