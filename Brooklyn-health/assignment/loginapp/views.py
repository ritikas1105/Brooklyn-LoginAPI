from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import boto3
from decouple import config
import hmac
import hashlib
import base64

AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_REGION_NAME = config('AWS_REGION_NAME')

cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION_NAME)

USER_POOL_ID = config('USER_POOL_ID')
CLIENT_ID = config('CLIENT_ID')
CLIENT_SECRET = config('CLIENT_SECRET')

def calculate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    dig = hmac.new(bytes(client_secret, 'latin-1'), msg=message.encode('utf-8'), digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

@login_required(login_url='login')
def HomePage(request):
    return render (request,'home.html')

@csrf_exempt
def LoginPage(request):
    if request.method=='POST':
        email=request.POST.get('username')  # Assuming 'username' field is used for email
        password=request.POST.get('pass')

        if not email or not password:
            return JsonResponse({
                "status": "fail",
                "message": "Email or password is missing",
                "result": None,
                "status_code": 400
            })

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({
                "status": "fail",
                "message": "Invalid email format",
                "result": None,
                "status_code": 400
            })

        User = get_user_model()
        if not User.objects.filter(email=email).exists():
            return JsonResponse({
                "status": "fail",
                "message": "User not found",
                "result": None,
                "status_code": 404
            })

        try:
            secret_hash = calculate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
            response = cognito_client.initiate_auth(
                ClientId= CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash,
                },
            )
            print("Response:", response)
            
        except cognito_client.exceptions.NotAuthorizedException as e:
            print("Exception:", e)
            response = cognito_client.list_users(UserPoolId=USER_POOL_ID)
            valid_users = [attr['Value'] for user in response['Users'] for attr in user['Attributes'] if attr['Name'] == 'email']
            print("Valid users:", valid_users)
            return JsonResponse({
                "status": "fail",
                "message": "Incorrect Email or Password",
                "status_code": 401
            })

        id_token = response['AuthenticationResult']['IdToken']

        return JsonResponse({
            "status": "success",
            "message": "Login successful",
            "result": {
                "id_token": id_token,
                "expires_in": response['AuthenticationResult']['ExpiresIn']
            },
            "status_code": 200
        })

    return render(request, 'login.html')