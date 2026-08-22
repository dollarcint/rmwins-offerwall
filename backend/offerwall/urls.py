from django.urls import path

from . import views


app_name = "offerwall"

urlpatterns = [
    path("admin-portal/login/", views.admin_portal_login, name="admin-login"),
    path(
        "admin-portal/password/",
        views.admin_portal_password_change,
        name="admin-password-change",
    ),
    path("admin-portal/logout/", views.admin_portal_logout, name="admin-logout"),
    path("admin-portal/", views.admin_portal_dashboard, name="admin-dashboard"),
    path(
        "admin-portal/inventory/",
        views.admin_portal_inventory,
        name="admin-inventory",
    ),
    path(
        "admin-portal/suppliers/",
        views.admin_portal_suppliers,
        name="admin-suppliers",
    ),
    path(
        "admin-portal/suppliers/<uuid:publisher_id>/",
        views.admin_portal_supplier_detail,
        name="admin-supplier-detail",
    ),
    path(
        "admin-portal/placements/",
        views.admin_portal_placements,
        name="admin-placements",
    ),
    path(
        "admin-portal/placements/<uuid:placement_id>/",
        views.admin_portal_placement_detail,
        name="admin-placement-detail",
    ),
    path(
        "admin-portal/respondents/",
        views.admin_portal_respondents,
        name="admin-respondents",
    ),
    path(
        "admin-portal/conversions/",
        views.admin_portal_conversions,
        name="admin-conversions",
    ),
    path(
        "admin-portal/billing/",
        views.admin_portal_billing,
        name="admin-billing",
    ),
    path(
        "admin-portal/postbacks/",
        views.admin_portal_postbacks,
        name="admin-postbacks",
    ),
    path(
        "admin-portal/reports/",
        views.admin_portal_reports,
        name="admin-reports",
    ),
    path(
        "admin-portal/activity/",
        views.admin_portal_activity,
        name="admin-activity",
    ),
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
        "publisher/sections/general-details/",
        views.publisher_general_details,
        name="publisher-general-details",
    ),
    path(
        "publisher/billing/",
        views.publisher_billing,
        name="publisher-billing",
    ),
    path(
        "publisher/billing/<uuid:statement_id>/",
        views.publisher_billing_statement,
        name="publisher-billing-statement",
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
