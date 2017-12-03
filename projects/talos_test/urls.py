from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include
from django.urls import path
from talos.urls import auth_url_patterns

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
    path('auth/', include(auth_url_patterns)),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
