from django.urls import path

from . import views


app_name = "offerwall"

urlpatterns = [
    path("wall/<slug:publisher_slug>/", views.wall_entry, name="entry"),
    path("wall/session/<uuid:visit_id>/", views.wall_session, name="session"),
    path(
        "wall/session/<uuid:visit_id>/go/<str:survey_id>/",
        views.click_offer,
        name="click",
    ),
    path("wall/result/<uuid:click_id>/", views.result, name="result"),
    path("api/v1/offerwall/offers/", views.offers_api, name="offers-api"),
    path("api/v1/offerwall/wallet/", views.wallet_api, name="wallet-api"),
    path(
        "publisher/access/<slug:publisher_slug>/",
        views.publisher_access,
        name="publisher-access",
    ),
    path("publisher/", views.publisher_dashboard, name="publisher-dashboard"),
    path(
        "publisher/withdrawals/",
        views.publisher_request_withdrawal,
        name="publisher-withdrawal",
    ),
    path("publisher/logout/", views.publisher_logout, name="publisher-logout"),
]
