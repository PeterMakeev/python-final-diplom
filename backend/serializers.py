from rest_framework import serializers

from backend.models import User, Category, Shop, ProductInfo, Product, ProductParameter, OrderItem, Order, Contact


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'company', 'position', 'type']
        read_only_fields = ['id']


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ['name', 'shops']


class ShopSerializer(serializers.ModelSerializer):

    class Meta:
        model = Shop
        fields = ['id', 'name', 'url', 'state']
        read_only_fields = ['id']


class ProductParameterSerializer(serializers.ModelSerializer):
     parameter = serializers.StringRelatedField()

     class Meta:
         model = ProductParameter
         fields = ['parameter', 'value']


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ['name', 'category']


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)

    class Meta:
        model = ProductInfo
        fields = ['id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters']
        read_only_fields = ['id']


class ContactSerializer(serializers.ModelSerializer):
    user = UserSerializer

    class Meta:
        model = Contact
        fields = ['id', 'user', 'phone', 'city', 'street', 'house']


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = ProductInfoSerializer
    #ordered_items = OrderItemCreateSerializer(read_only=True, many=True)
    total_sum = serializers.IntegerField()
    contact = ContactSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ['id', 'ordered_items', 'state', 'dt', 'total_sum', 'contact']
        read_only_fields = ['id']


class OrderItemSerializer(serializers.ModelSerializer):
    order = OrderSerializer
    product_info = ProductInfoSerializer


    class Meta:
        model = OrderItem
        fields = ['id', 'product_info', 'quantity', 'order']
        read_only_fields = ['id']
        extra_kwargs = {
            'order': {'write_only': True}
        }
