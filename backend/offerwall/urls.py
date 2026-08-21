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
]
