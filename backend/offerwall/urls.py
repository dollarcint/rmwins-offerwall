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
    path(
        "offerwall/clickTrackingLink/",
        views.offer_click_tracking,
        name="offer-click-tracking",
    ),
    path("api/v1/offerwall/wallet/", views.wallet_api, name="wallet-api"),
    path("publisher/login/", views.supplier_login, name="supplier-login"),
    path("publisher/signup/", views.supplier_signup, name="supplier-signup"),
    path(
        "publisher/access/<slug:publisher_slug>/",
        views.publisher_access,
        name="publisher-access",
    ),
    path("publisher/", views.publisher_dashboard, name="publisher-dashboard"),
    path(
        "publisher/placements/",
        views.publisher_placements,
        name="publisher-placements",
    ),
    path(
        "publisher/placements/<uuid:placement_id>/edit/",
        views.publisher_placement_edit,
        name="publisher-placement-edit",
    ),
    path(
        "publisher/placements/<uuid:placement_id>/action/",
        views.publisher_placement_action,
        name="publisher-placement-action",
    ),
    path(
        "publisher/placements/<uuid:placement_id>/postbacks/new/",
        views.publisher_placement_event_postback_add,
        name="publisher-placement-event-postback-add",
    ),
    path(
        "publisher/placements/<uuid:placement_id>/postbacks/<uuid:postback_id>/action/",
        views.publisher_placement_event_postback_action,
        name="publisher-placement-event-postback-action",
    ),
    path(
        "publisher/placements/<uuid:placement_id>/postback-test/",
        views.publisher_placement_postback_test,
        name="publisher-placement-postback-test",
    ),
    path(
        "publisher/sections/<slug:section>/",
        views.publisher_section,
        name="publisher-section",
    ),
    path(
        "publisher/respondents/<uuid:respondent_id>/action/",
        views.publisher_respondent_action,
        name="publisher-respondent-action",
    ),
    path(
        "publisher/withdrawals/",
        views.publisher_request_withdrawal,
        name="publisher-withdrawal",
    ),
    path("publisher/logout/", views.publisher_logout, name="publisher-logout"),
    path(
        "embed/app/<str:app_id>/",
        views.placement_app_embed,
        name="placement-app-embed",
    ),
    path(
        "embed/<uuid:placement_id>/",
        views.placement_embed,
        name="placement-embed",
    ),
    path(
        "brand/<uuid:placement_id>/<slug:kind>/",
        views.placement_brand_asset,
        name="placement-brand-asset",
    ),
    path("operations/", views.offerwall_operations, name="operations"),
    path(
        "operations/action/",
        views.offerwall_operations_action,
        name="operations-action",
    ),
]
