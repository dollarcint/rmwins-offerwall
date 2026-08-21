"""Root routing for workspace apps, APIs, admin and protected documentation."""

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from accounts.views import throttled_admin_login

from .api_docs import DocumentationProtectionMixin, IsDocumentationAdmin


class ProtectedSchemaView(DocumentationProtectionMixin, SpectacularAPIView):
    permission_classes = [IsDocumentationAdmin]


class ProtectedSwaggerView(DocumentationProtectionMixin, SpectacularSwaggerView):
    permission_classes = [IsDocumentationAdmin]


class ProtectedRedocView(DocumentationProtectionMixin, SpectacularRedocView):
    permission_classes = [IsDocumentationAdmin]


urlpatterns = [
    path("admin/login/", throttled_admin_login, name="throttled-admin-login"),
    path("admin/", admin.site.urls),
    path("api/schema/", ProtectedSchemaView.as_view(), name="api-schema"),
    path("api/docs/", ProtectedSwaggerView.as_view(url_name="api-schema"), name="swagger-ui"),
    path("api/redoc/", ProtectedRedocView.as_view(url_name="api-schema"), name="redoc"),
    path("api/v1/access/", include("accounts.api_urls")),
    path("api/v1/vendors/", include("vendors.urls")),
    path("", include("offerwall.urls")),
    path("", include("vendors.web_urls")),
    path("", include("accounts.urls")),
    path("", include("surveys.urls")),
]
