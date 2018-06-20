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

from django.urls import path, re_path
from .views import (BasicLoginAPIView, PrincipalRegistrationRequestEditAPIView,
                    PrincipalRegistrationConfirmationAPIView,
                    PrincipalRegistrationTokenValidationAPIView,
                    LogoutAPIView,
                    EmailChangeRequestEditAPIView,
                    EmailChangeConfirmEditAPIView)

from rest_framework.documentation import include_docs_urls

urlpatterns = [
    path('docs/', include_docs_urls(title='My API title', public=False, description='test')),

    # METHOD POST domain/v1/session
    path('basic_login/', BasicLoginAPIView.as_view(), name='talos-basic-login'),
    # METHOD DELETE domain/v1/session
    path('logout', LogoutAPIView.as_view()),

    path('principal', PrincipalRegistrationRequestEditAPIView.as_view(),
         name='talos-rest-principal-regisration-request'),
    path('token/<slug:secret>',
         PrincipalRegistrationTokenValidationAPIView.as_view(),
         name='talos-principal-token-validation'),
    path('principal-registration-confirm-edit/<slug:secret>',
         PrincipalRegistrationConfirmationAPIView.as_view(),
         name='talos-principal-registration-confirm-edit'),

    path('email-change-request-edit/', EmailChangeRequestEditAPIView.as_view(), name='talos-email-change-request-edit'),
    path('email-change-confirm-edit/<slug:secret>', EmailChangeConfirmEditAPIView.as_view(), name='talos-email-change-confirm-edit'),
    # TODO VERSIONING
    # re_path(r'^(?P<version>(v1|v2))/bookings/$',BasicLoginAPIView.as_view(),name='bookings-list'),
]
