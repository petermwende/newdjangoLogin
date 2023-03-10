from django.shortcuts import render, redirect
from . import views
from django.http import Httpresponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from Login import settings
from django.core.mail import send_email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from tokens import generate.token('email_confirmation.html')

#create your views here.
def home(request):
    return render(request, 'index.html')

def signup(request):
    if request.method == "POST":
        Username = request.POST.get('username')
        Fname = request.POST.get('fname')
        Lname = request.POST.get('lname')
        Email = request.POST.get('email')
        Pass1 = request.POST.get('pass1')
        Pass2 = request.POST.get('pass2')

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists.Please try another name")
            return redirect('home')

        if len(username)>10:
            messages.error(request, "Username must be upto 10 characters")

        if pass1 = pass2
            messages.error(request, "Passwords mismatch")

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric")
            return redirect('home')


        myuser = User.objects.create_user(Username,Email,Pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        message.success(request, "Your account has been created successfully.")

    # Welcome email
    subject = "Welcome to djangoLoginSystem"
    message = "Hello" + myuser.first_name + "!! \n" + "Welcome to LoginSystem \n Thankyou for visiting our website \n We have sent you a confirmation email to confirm your email address to activate your account \n\n Thanks\n"
    from_email = settings.EMAIL_HOST_USER
    to_list = [myuser.email]
    send_mail(subject, message, from_email, to_list, fail_silently=True)

    # Email Address Confirmation Email

    current_site = get_current_site(request)
    email_subject = "Confirm your email @ djangoLoginSystem - DjangoLoginSystem||"
    message2 = render_to_string('email_confirmation.html'),{
        'name': myuser.first_name,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_byte(myuser.pk)),
        'token': generate_token.make_token(myuser)
    }

    email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER
        [myuser.email],
    )
    email.fail_silently = True
    email.send()

        return redirect('Signin')
        return render(request, 'signup.html')

def signin(request):
    if request.method == POST:
        Username = request.POST.get('username')
        Pass1 = request.POST.get('pass1')

        user = authenticate(username=Username, password=Pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'index.html',{'fname':fname})
        else:
            messages.error(request, "Wrong credentials")
            return redirect('Home')

    return render(request, 'signin.html')

def signin(request):
    return render(request, 'signin.html')

def signout(request):
    logout(request)
    messages.success(request, "Successfully logged out")
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_encode())
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')