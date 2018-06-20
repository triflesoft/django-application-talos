"""talos_test URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from talos.urls import auth_url_patterns
from .views import BasicLoginAPIView, PrincipalRegistrationRequestEditAPIView, PrincipalRegistrationConfirmationAPIView

from django.views.decorators.csrf import csrf_exempt


urlpatterns = [
    path('basic_login/', BasicLoginAPIView.as_view(), name='talos-basic-login'),
    path('principal-registration-request-edit/', PrincipalRegistrationRequestEditAPIView.as_view(),
         name='talos-principal-registration-request-edit'),
    path('principal-registration-confirm-edit/<slug:secret>', PrincipalRegistrationConfirmationAPIView.as_view(), name='talos-principal-registration-confirm-edit'),

]