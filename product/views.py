from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Products
from .serializer import ProductSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
class ProductAPIView(APIView):
    #authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request, pk=None):
       
        try:
            if pk is not None:
                product = self.get_object(pk)
                serializer = ProductSerializer(product)
                return Response(serializer.data)
            else:
                products = Products.objects.all()
                #print(product)
                product = Products.objects.last()
                #print(product.id)
                serializer = ProductSerializer(products, many=True)
                return Response(serializer.data)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            product = Products.objects.last()
            print(product.id)
            request.data["product_id"] = "pId_00" + str(product.id + 1)
            serializer = ProductSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_object(self, pk):
        try:
            return Products.objects.get(product_id=pk)
        except Products.DoesNotExist:
            # Raise an appropriate exception or return a response with the relevant status code
            return Response({"detail": "Product does not exist."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        try:
            product = self.get_object(pk)
            serializer = ProductSerializer(product, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            product = self.get_object(pk)
            product.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            # Handle the exception here, you can log the error or return an appropriate response
            return Response({'message': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
