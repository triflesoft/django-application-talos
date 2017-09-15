from django.conf import settings
from django.conf.urls import include
from django.conf.urls import url
from django.conf.urls.static import static
from django.contrib import admin
from talos.urls import auth_url_patterns

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^accounts/', include('django.contrib.auth.urls')),
    url(r'^auth/', include(auth_url_patterns)),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
