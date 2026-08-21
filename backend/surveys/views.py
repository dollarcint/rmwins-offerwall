"""Workspace pages, respondent flow, callbacks, reports, exports and REST APIs.

Business writes are delegated to survey/provider/allocation/vault services where
possible. Public respondent endpoints live here because they coordinate several
of those services inside one guarded request lifecycle.
"""

import csv
import ipaddress
import json
import logging
import re
from datetime import date, timedelta
from decimal import Decimal
from types import SimpleNamespace
from urllib.parse import quote, urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import Count, F, IntegerField, Max, OuterRef, Q, Subquery, Sum, Value
from django.db.models.functions import Coalesce
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.core.paginator import Paginator
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import filters, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.access import (
    HasFunctionPermission,
    activity_visible_user_ids,
    effective_permission_codes,
    function_permission_required,
    has_function_access,
)
from vendors.services import (
    AllocationUnavailable,
    annotate_survey_pricing_for_user,
    finalize_attempt_capacity,
    reserve_attempt_capacity,
    resolve_vendor_survey_context,
    organization_client_ids_for_user,
    scope_surveys_for_api_key,
    scope_surveys_for_user,
    visible_amount_for_user,
    visible_cpi_for_user,
)
from vendors.access import is_external_vendor_scope, vendor_scope_user_id
from vendors.models import VendorAPIKey

from .filters import SurveyAttemptFilter, SurveyFilter
from .forms import ManualSurveyForm
from .dashboard import (
    build_dashboard_payload,
    dashboard_attempts,
    dashboard_client_options,
    dashboard_range_window,
)
from .excel import ExcelSheet, build_excel_response
from .integrations import InnovateMRAPIError, InnovateMRClient
from .innovatemr_callbacks import (
    CallbackConfigurationError,
    UPSTREAM_STATUS_MAP as INNOVATEMR_STATUS_MAP,
    verify_callback_hash,
)
from .models import CanonicalQuestion, ProviderQuestionMapping, Survey, SurveyAttempt, SyncRun
from .outcomes import provider_outcome
from .report_pricing import (
    apply_percentage,
    can_view_report_commercials,
    role_visibility_percent,
    supplier_cpi_for_admin,
    supplier_label_for_admin,
    viewer_attempt_cpi,
)
from .serializers import (
    SurveyDetailSerializer,
    DashboardResponseSerializer,
    CanonicalQuestionSerializer,
    ProviderQuestionMappingSerializer,
    SurveyListSerializer,
    SurveyAttemptSerializer,
    SurveyAttemptListResponseSerializer,
    SurveyQuotaSerializer,
    RFGCallbackResponseSerializer,
    SyncRunSerializer,
    SyncTriggerResponseSerializer,
    TargetingQuestionSerializer,
    UserHitsResponseSerializer,
)
from .pagination import SurveyPagination
from .project_cache import project_filter_metadata
from prescreener_vault.services import (
    PrescreenerVaultError,
    answers_with_entry_postal_code,
    capture_prescreener_submission,
    operational_answer_value,
    wrong_target_country_answers,
)
from prescreener_vault.cint_email_pool import CintEmailPoolExhausted
from prescreener_vault.models import PrescreenerSubmission
from prescreener_vault.reuse import maybe_assign_reusable_profile
from prescreener_vault.cache import (
    apply_submission_filters,
    vault_filter_options,
    vault_filtered_summary,
)
from .providers import ProviderError, get_provider, has_provider
from .providers.base import close_provider, managed_provider
from .geolocation import (
    geolocation_client_data,
    is_wrong_target_country,
    resolve_entry_geolocation,
    survey_target_country_code,
)
from .rfg_outcomes import RFG_STATUS_MAP, describe_rfg_outcome
from .rfg_text import clean_rfg_display_text
from .services import reconcile_attempt_status, replace_survey_quotas, replace_survey_targeting, sync_surveys
from .survey_flow import (
    backfill_attempt_entry_audit,
    build_outbound_url,
    create_attempt,
    ensure_attempt_prescreener_uid,
    get_request_client_data,
    get_request_ip,
    status_identifiers_from_request,
    status_rid_from_request,
)
from .tasks import sync_innovatemr_surveys_task
from .user_hits import aggregate_user_hits, user_hit_filter_options


logger = logging.getLogger(__name__)


class UpstreamUnavailable(APIException):
    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = "InnovateMR is temporarily unavailable and no cached survey detail exists."
    default_code = "upstream_unavailable"


PROJECT_COLUMN_PERMISSIONS = {
    "project_id": "projects.column.project_id", "survey": "projects.column.survey",
    "market": "projects.column.market", "completes": "projects.column.completes",
    "cpi": "projects.column.cpi", "loi_ir": "projects.column.loi_ir",
    "entry_link": "projects.column.entry_link", "modified": "projects.column.modified",
    "actions": "projects.column.actions",
}

PROJECT_FILTER_PERMISSIONS = {
    "search": "projects.filter.search", "country": "projects.filter.country",
    "status": "projects.filter.status", "client": "projects.filter.client",
    "buyer": "projects.filter.buyer", "survey_type": "projects.filter.survey_type",
    "cpi": "projects.filter.cpi", "date": "projects.filter.date",
    "clear": "projects.filters.clear",
}

STUDY_COLUMN_PERMISSIONS = {
    "project_id": "studies.column.project_id", "survey_id": "studies.column.survey_id",
    "country": "studies.column.country", "cpi": "studies.column.cpi",
    "respondent_id": "studies.column.respondent_id", "pid": "studies.column.pid",
    "user": "studies.column.user",
    "device": "studies.column.device", "ip": "studies.column.ip", "loi": "studies.column.loi",
    "status": "studies.column.status", "start": "studies.column.start", "end": "studies.column.end",
}

STUDY_FILTER_PERMISSIONS = {
    "search": "studies.filter.search", "branch": "studies.filter.branch",
    "sub_branch": "studies.filter.sub_branch", "shift": "studies.filter.shift", "user": "studies.filter.user",
    "status": "studies.filter.status", "country": "studies.filter.country",
    "client": "studies.filter.client", "buyer": "studies.filter.buyer",
    "project": "studies.filter.project", "date": "studies.filter.date",
    "clear": "studies.filters.clear",
}

DASHBOARD_FILTER_PERMISSIONS = {
    "client": "dashboard.filter.client", "country": "dashboard.filter.country",
    "branch": "dashboard.filter.branch", "sub_branch": "dashboard.filter.sub_branch",
    "shift": "dashboard.filter.shift", "user": "dashboard.filter.user",
    "date": "dashboard.filter.date", "clear": "dashboard.filters.clear",
}

DASHBOARD_CARD_PERMISSIONS = {
    "hits": "dashboard.card.hits", "completes": "dashboard.card.completes",
    "conversion_rate": "dashboard.card.conversion", "active_users": "dashboard.card.active_users",
    "average_loi_seconds": "dashboard.card.average_loi", "revenue": "dashboard.card.revenue",
    "average_cpi": "dashboard.card.average_cpi", "rpc": "dashboard.card.rpc",
    "incidence_rate": "dashboard.card.ir",
}

DASHBOARD_CHART_PERMISSIONS = {
    "performance": "dashboard.chart.performance", "client_share": "dashboard.chart.client_share",
    "status": "dashboard.chart.status", "device": "dashboard.chart.device",
    "top_users": "dashboard.chart.top_users",
}

DASHBOARD_GRAPH_FILTER_PERMISSIONS = {
    "traffic": "dashboard.graph.traffic_filters",
    "finance": "dashboard.graph.finance_filters",
}

STUDY_CARD_PERMISSIONS = {
    "total": "studies.card.total", "initiated": "studies.card.initiated",
    "completed": "studies.card.completed", "terminated": "studies.card.terminated",
    "quota": "studies.card.quota", "security": "studies.card.security",
    "conversion": "studies.card.conversion", "desktop": "studies.card.desktop",
    "mobile": "studies.card.mobile", "tablet": "studies.card.tablet",
    "revenue": "studies.card.revenue",
    "ir": "studies.card.ir",
}

USER_HIT_COLUMN_PERMISSIONS = {
    "branch": "user_hits.column.branch", "sub_branch": "user_hits.column.sub_branch", "shift": "user_hits.column.shift",
    "user": "user_hits.column.user", "date": "user_hits.column.date",
    "hits": "user_hits.column.hits", "completes": "user_hits.column.completes",
}

USER_HIT_FILTER_PERMISSIONS = {
    "search": "user_hits.filter.search", "branch": "user_hits.filter.branch",
    "sub_branch": "user_hits.filter.sub_branch", "shift": "user_hits.filter.shift", "user": "user_hits.filter.user",
    "date": "user_hits.filter.date", "clear": "user_hits.filters.clear",
}

USER_HIT_CARD_PERMISSIONS = {
    "total_hits": "user_hits.card.total_hits", "completes": "user_hits.card.completes",
    "conversion": "user_hits.card.conversion", "active_users": "user_hits.card.active_users",
    "devices": "user_hits.card.devices", "ir": "user_hits.card.ir",
}

TERM_REASON_FIELD_PERMISSIONS = {
    "status": "termination_reasons.field.status",
    "reason": "termination_reasons.field.reason",
    "respondent": "termination_reasons.field.respondent",
    "survey": "termination_reasons.field.survey",
    "timing": "termination_reasons.field.timing",
    "audit": "termination_reasons.field.audit",
}

TERM_REASON_COLUMN_PERMISSIONS = {
    "rid": "termination_reasons.column.rid",
    "survey": "termination_reasons.column.survey",
    "client": "termination_reasons.column.client",
    "respondent": "termination_reasons.column.respondent",
    "status": "termination_reasons.column.status",
    "ended": "termination_reasons.column.ended",
    "actions": "termination_reasons.column.actions",
}

TERM_REASON_FILTER_PERMISSIONS = {
    "rid": "termination_reasons.filter.rid",
    "branch": "termination_reasons.filter.branch",
    "sub_branch": "termination_reasons.filter.sub_branch",
    "shift": "termination_reasons.filter.shift",
    "user": "termination_reasons.filter.user",
    "status": "termination_reasons.filter.status",
    "country": "termination_reasons.filter.country",
    "client": "termination_reasons.filter.client",
    "buyer": "termination_reasons.filter.buyer",
    "date": "termination_reasons.filter.date",
    "clear": "termination_reasons.filters.clear",
}

TERM_REASON_CARD_PERMISSIONS = {
    "total": "termination_reasons.card.total",
    "terminated": "termination_reasons.card.terminated",
    "quota": "termination_reasons.card.quota",
    "quality": "termination_reasons.card.quality",
}

PRESCREENER_DATA_FILTER_PERMISSIONS = {
    "search": "prescreener_data.filter.search",
    "country": "prescreener_data.filter.country",
    "language": "prescreener_data.filter.language",
    "age_group": "prescreener_data.filter.age_group",
    "gender": "prescreener_data.filter.gender",
    "clear": "prescreener_data.filters.clear",
}

PRESCREENER_DATA_COLUMN_PERMISSIONS = {
    "uid": "prescreener_data.column.uid",
    "market": "prescreener_data.column.market",
    "profile": "prescreener_data.column.profile",
    "captured": "prescreener_data.column.captured",
    "usage_count": "prescreener_data.column.usage_count",
    "answers": "prescreener_data.column.answers",
}

UNSUCCESSFUL_STATUS_LABELS = {
    SurveyAttempt.Status.TERMINATED: "Terminated",
    SurveyAttempt.Status.OVER_QUOTA: "Quota full",
    SurveyAttempt.Status.QUALITY_TERMINATED: "Quality / security",
}
UNSUCCESSFUL_ATTEMPT_STATUSES = set(UNSUCCESSFUL_STATUS_LABELS)


def _project_columns_for_user(user):
    codes = effective_permission_codes(user)
    columns = [name for name, code in PROJECT_COLUMN_PERMISSIONS.items() if code in codes]
    if "entry_link" in columns and "survey_links.copy" not in codes:
        columns.remove("entry_link")
    if "actions" in columns and "survey_details.view" not in codes:
        columns.remove("actions")
    return columns


def _component_access(codes, permissions):
    return {name: code in codes for name, code in permissions.items()}


def _permitted_columns(codes, permissions):
    return [name for name, code in permissions.items() if code in codes]


def _enforce_query_permissions(request, permission_parameters):
    permission_codes = None
    for code, parameters in permission_parameters.items():
        if any(request.query_params.get(parameter) not in {None, ""} for parameter in parameters):
            if permission_codes is None:
                permission_codes = effective_permission_codes(request.user)
            if not (
                request.user.is_active and request.user.is_superuser
            ) and code not in permission_codes:
                raise PermissionDenied(f"Your account cannot use the {code} filter.")


class NullsLastOrderingFilter(filters.OrderingFilter):
    """Translate selected nullable API sorts into cross-database expressions."""

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)
        if not ordering:
            return queryset

        nullable_fields = set(getattr(view, "nulls_last_ordering_fields", ()))
        expressions = []
        for term in ordering:
            if not isinstance(term, str):
                expressions.append(term)
                continue
            descending = term.startswith("-")
            field_name = term[1:] if descending else term
            if field_name not in nullable_fields:
                expressions.append(term)
                continue
            expression = F(field_name)
            expressions.append(
                expression.desc(nulls_last=True)
                if descending
                else expression.asc(nulls_last=True)
            )
        return queryset.order_by(*expressions)


@function_permission_required("dashboard.view")
def dashboard_page(request):
    codes = effective_permission_codes(request.user)
    return render(request, "surveys/dashboard.html", {
        "active_page": "dashboard",
        "dashboard_cards": _permitted_columns(codes, DASHBOARD_CARD_PERMISSIONS),
        "dashboard_charts": _permitted_columns(codes, DASHBOARD_CHART_PERMISSIONS),
        "dashboard_graph_filters": _permitted_columns(
            codes, DASHBOARD_GRAPH_FILTER_PERMISSIONS
        ),
    })


@function_permission_required("projects.view")
def projects_page(request):
    codes = effective_permission_codes(request.user)
    inventory_surveys = Survey.objects.filter(
        Q(integration__isnull=True) | Q(integration__is_active=True)
    )
    visible_surveys = annotate_survey_pricing_for_user(
        scope_surveys_for_user(inventory_surveys, request.user),
        request.user,
    )
    is_client_scoped_panel = bool(
        vendor_scope_user_id(request.user) or organization_client_ids_for_user(request.user) is not None
    )
    project_columns = _project_columns_for_user(request.user)
    project_filters = _component_access(codes, PROJECT_FILTER_PERMISSIONS)
    can_sort_cpi = project_filters["cpi"]
    metadata = project_filter_metadata(
        visible_surveys,
        user_id=request.user.pk,
        client_scoped=is_client_scoped_panel,
        include_cpi=can_sort_cpi,
        cpi_field="visible_cpi",
    )
    cpi_min, cpi_max = 0, 100
    if can_sort_cpi:
        cpi_min = metadata["cpi_min"] or 0
        cpi_max = metadata["cpi_max"] or 100
        if cpi_max <= cpi_min:
            cpi_max = cpi_min + 1
    return render(request, "surveys/projects.html", {
        "active_page": "projects",
        "countries": metadata["countries"],
        "companies": metadata["companies"],
        "buyer_options": metadata["buyer_options"],
        "survey_types": metadata["survey_types"],
        "company_filter_label": "Client",
        "company_filter_param": "client_name" if is_client_scoped_panel else "company",
        "company_filter_default": "All clients",
        "project_columns": project_columns, "project_column_count": max(1, len(project_columns)),
        "can_view_project_client_name": "projects.column.client_name" in codes,
        "project_filters": project_filters,
        "can_sync": "sync.run" in codes,
        "can_export_projects": "projects.export" in codes,
        "can_change_project_page_size": "projects.control.page_size" in codes,
        "can_paginate_projects": "projects.control.pagination" in codes,
        "can_open_project_studies": "attempts.view" in codes and "studies.filter.project" in codes,
        "can_sort_cpi": can_sort_cpi, "cpi_min_bound": cpi_min, "cpi_max_bound": cpi_max,
    })


@function_permission_required("projects.manual.create")
@require_http_methods(["GET", "POST"])
def manual_survey_create(request):
    """Create inventory for a client that supplies links instead of an API feed."""

    created_survey = None
    if request.method == "POST":
        form = ManualSurveyForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    created_survey = form.save(created_by=request.user)
            except IntegrityError:
                form.add_error(
                    "source_key",
                    "A manual survey with this client survey ID already exists.",
                )
            else:
                return HttpResponseRedirect(
                    f"{reverse('manual-survey-create')}?created={created_survey.local_id}"
                )
    else:
        form = ManualSurveyForm(initial={
            "rid_parameter": "pid",
            "survey_type": "B2C",
            "device_type": "All",
        })
        created_code = (request.GET.get("created") or "").strip()
        if created_code:
            created_survey = Survey.objects.filter(
                local_id=created_code,
                inventory_source=Survey.InventorySource.MANUAL,
                created_by=request.user,
            ).first()

    start_link = ""
    if created_survey:
        start_query = urlencode({
            "surveyId": created_survey.source_identifier,
            "supplierCode": settings.PUBLIC_SUPPLIER_CODE,
            "userId": request.user.pk,
            "code": created_survey.local_id,
        })
        start_link = request.build_absolute_uri(
            f"{reverse('survey-start')}?{start_query}"
        )
    return render(request, "surveys/manual_survey_form.html", {
        "active_page": "manual-survey",
        "form": form,
        "created_survey": created_survey,
        "start_link": start_link,
    })


@function_permission_required("attempts.view")
def studies_page(request):
    codes = effective_permission_codes(request.user)
    user_ids = activity_visible_user_ids(request.user)
    hierarchy_options = user_hit_filter_options(request.user)
    visible_attempts = SurveyAttempt.objects.all()
    if not request.user.is_superuser:
        visible_attempts = visible_attempts.filter(platform_user_id__in=user_ids)
    visible_surveys = scope_surveys_for_user(Survey.objects.all(), request.user)
    countries = list(
        visible_surveys.exclude(country_code="")
        .values("country_code", "country")
        .distinct().order_by("country_code")
    )
    study_clients = list(
        visible_attempts.filter(survey__client__isnull=False)
        .values("survey__client_id", "survey__client__name")
        .distinct().order_by("survey__client__name")
    )
    study_buyers = list(
        visible_attempts.exclude(survey__buyer_id="")
        .values("survey__buyer_id", "survey__client_id")
        .distinct().order_by("survey__buyer_id")
    )
    return render(request, "surveys/studies.html", {
        "active_page": "studies",
        "tracked_users": hierarchy_options["users"],
        "study_branches": hierarchy_options["branches"],
        "study_sub_branches": hierarchy_options["sub_branches"],
        "study_shifts": hierarchy_options["shifts"],
        "study_countries": countries,
        "study_clients": study_clients,
        "study_buyers": study_buyers,
        "attempt_statuses": [
            ("initiated,redirected", "Initiated"),
            (SurveyAttempt.Status.COMPLETED, "Completed"),
            (SurveyAttempt.Status.TERMINATED, "Terminated"),
            (SurveyAttempt.Status.OVER_QUOTA, "Over quota"),
            (SurveyAttempt.Status.QUALITY_TERMINATED, "Quality terminated"),
        ],
        "study_filters": _component_access(codes, STUDY_FILTER_PERMISSIONS),
        "study_columns": _permitted_columns(codes, STUDY_COLUMN_PERMISSIONS),
        "study_column_count": max(1, len(_permitted_columns(codes, STUDY_COLUMN_PERMISSIONS))),
        "study_cards": _permitted_columns(codes, STUDY_CARD_PERMISSIONS),
        "can_export": "attempts.export" in codes,
        "can_change_study_page_size": "studies.control.page_size" in codes,
        "can_paginate_studies": "studies.control.pagination" in codes,
    })


@function_permission_required("user_hits.view")
def user_hits_page(request):
    codes = effective_permission_codes(request.user)
    return render(request, "surveys/user_hits.html", {
        "active_page": "user-hits",
        "hit_filters": _component_access(codes, USER_HIT_FILTER_PERMISSIONS),
        "hit_columns": _permitted_columns(codes, USER_HIT_COLUMN_PERMISSIONS),
        "hit_column_count": max(1, len(_permitted_columns(codes, USER_HIT_COLUMN_PERMISSIONS))),
        "hit_cards": _permitted_columns(codes, USER_HIT_CARD_PERMISSIONS),
        "can_change_hit_page_size": "user_hits.control.page_size" in codes,
        "can_paginate_hits": "user_hits.control.pagination" in codes,
        **user_hit_filter_options(request.user),
    })


@function_permission_required("prescreener_data.view")
def prescreener_data_page(request):
    """Read-only, permission-scoped Panelist Data browser for the isolated vault."""

    codes = effective_permission_codes(request.user)
    filters_access = _component_access(codes, PRESCREENER_DATA_FILTER_PERMISSIONS)
    columns = _permitted_columns(codes, PRESCREENER_DATA_COLUMN_PERMISSIONS)
    selected = {
        "search": request.GET.get("search", "").strip(),
        "country": request.GET.get("country", "").strip(),
        "language": request.GET.get("language", "").strip(),
        "age_group": request.GET.get("age_group", "").strip(),
        "gender": request.GET.get("gender", "").strip(),
    }
    for name, value in selected.items():
        if value and not filters_access[name]:
            raise PermissionDenied(f"Your account cannot use the {name.replace('_', ' ')} filter.")

    page_obj = None
    summary = {"total": 0, "countries": 0, "age_groups": 0, "genders": 0}
    options = {"countries": [], "languages": [], "age_groups": [], "genders": []}
    vault_error = ""
    if not getattr(settings, "PRESCREENER_VAULT_ENABLED", False):
        vault_error = "The pre-screener vault is not enabled on this environment."
    else:
        try:
            base = PrescreenerSubmission.objects.using("prescreener_vault").all()
            options = vault_filter_options()
            queryset = apply_submission_filters(
                base.prefetch_related("question_answers"), selected
            )
            summary = vault_filtered_summary(selected)
            page_obj = Paginator(queryset.order_by("-submitted_at"), 20).get_page(request.GET.get("page", 1))
        except (DatabaseError, PrescreenerVaultError) as exc:
            logger.exception("Unable to read the pre-screener vault")
            vault_error = f"Vault data is temporarily unavailable: {exc}"

    query_without_page = request.GET.copy()
    query_without_page.pop("page", None)
    return render(request, "surveys/prescreened_data.html", {
        "active_page": "prescreened-data",
        "vault_error": vault_error,
        "page_obj": page_obj,
        "summary": summary,
        "options": options,
        "selected": selected,
        "vault_filters": filters_access,
        "vault_columns": columns,
        "vault_column_count": max(1, len(columns)),
        "can_export_vault": "prescreener_data.export" in codes,
        "can_paginate_vault": "prescreener_data.control.pagination" in codes,
        "page_query": query_without_page.urlencode(),
    })


@function_permission_required("prescreener_data.export")
def prescreener_data_export(request):
    """Export the filtered vault as analysis-friendly submission and answer sheets."""

    if not getattr(settings, "PRESCREENER_VAULT_ENABLED", False):
        return HttpResponse("The pre-screener vault is not enabled.", status=503)

    codes = effective_permission_codes(request.user)
    filters_access = _component_access(codes, PRESCREENER_DATA_FILTER_PERMISSIONS)
    selected = {
        "search": request.GET.get("search", "").strip(),
        "country": request.GET.get("country", "").strip(),
        "language": request.GET.get("language", "").strip(),
        "age_group": request.GET.get("age_group", "").strip(),
        "gender": request.GET.get("gender", "").strip(),
    }
    for name, value in selected.items():
        if value and not filters_access[name]:
            raise PermissionDenied(f"Your account cannot use the {name.replace('_', ' ')} filter.")

    queryset = apply_submission_filters(
        PrescreenerSubmission.objects.using("prescreener_vault").all(), selected
    )
    queryset = queryset.prefetch_related("question_answers").order_by("-submitted_at")

    def submission_rows():
        for submission in queryset.iterator(chunk_size=500):
            yield [
                submission.uid, submission.country, submission.country_code,
                submission.language, submission.language_code, submission.respondent_age,
                submission.respondent_age_group, submission.respondent_gender,
                submission.respondent_ethnicity, submission.respondent_postal_code,
                submission.usage_count, _excel_datetime(submission.submitted_at),
                _excel_datetime(submission.captured_at),
            ]

    def answer_rows():
        for submission in queryset.iterator(chunk_size=250):
            for answer in submission.question_answers.all():
                yield [
                    submission.uid, answer.position, answer.question_id,
                    answer.question_key, answer.question_text, answer.question_type,
                    answer.question_category, answer.canonical_attribute,
                    ", ".join(str(value) for value in answer.answer_values),
                    ", ".join(str(value) for value in answer.answer_labels),
                    ", ".join(str(value) for value in answer.upstream_values),
                ]

    local_now = timezone.localtime()
    return build_excel_response(
        f"panelist-data-{local_now:%Y%m%d-%H%M%S}-IST.xlsx",
        [
            ExcelSheet(
                "Submissions",
                ["UID", "Country", "Country code", "Language", "Language code", "Age", "Age group", "Gender", "Ethnicity", "ZIP / postal code", "Visits", "Registered at (IST)", "Captured at (IST)"],
                submission_rows(),
                [22, 20, 13, 17, 14, 9, 13, 14, 24, 18, 13, 22, 22],
            ),
            ExcelSheet(
                "Answers",
                ["UID", "Position", "Question ID", "Question key", "Question", "Question type", "Category", "Reusable attribute", "Answer values", "Answer labels", "Upstream values"],
                answer_rows(),
                [22, 10, 16, 22, 48, 18, 18, 20, 28, 34, 25],
            ),
        ],
    )


def _refresh_provider_outcome(attempt, integration):
    """Fetch one provider transaction without coupling custom clients to Innovate status rules."""

    provider_code = (integration.provider_code if integration else "innovatemr").lower()
    with managed_provider(InnovateMRClient(integration=integration)) as client:
        if provider_code == "innovatemr":
            reconcile_attempt_status(client, attempt)
            attempt.refresh_from_db()
            return

        survey_identifier = attempt.survey.source_id or attempt.survey.source_key
        transactions = client.get_survey_transactions_by_pid(survey_identifier, attempt.rid)
        if not transactions:
            attempt.upstream_checked_at = timezone.now()
            attempt.save(update_fields=["upstream_checked_at", "updated_at"])
            return

        respondent_keys = ("PID", "pid", "trackId", "rid", "RID", "respondentId")
        transaction_row = next(
            (
                row for row in transactions
                if any(str(row.get(key) or "") == attempt.rid for key in respondent_keys)
            ),
            transactions[0],
        )
        attempt.upstream_transaction_data = transaction_row
        attempt.upstream_checked_at = timezone.now()
        attempt.save(update_fields=["upstream_transaction_data", "upstream_checked_at", "updated_at"])


def _term_report_values(request, name):
    """Return stable, de-duplicated values from repeated or CSV query params."""

    values = []
    for raw_value in request.GET.getlist(name):
        for value in str(raw_value or "").split(","):
            value = value.strip()
            if value and value not in values:
                values.append(value)
    return values


def _term_report_filter_state(request, filters_access):
    selected = {
        "search": request.GET.get("search", "").strip(),
        "branch": _term_report_values(request, "branch"),
        "sub_branch": _term_report_values(request, "sub_branch"),
        "shift": _term_report_values(request, "shift"),
        "user": _term_report_values(request, "user"),
        "status": _term_report_values(request, "status"),
        "country": _term_report_values(request, "country"),
        "client": _term_report_values(request, "client"),
        "buyer_id": _term_report_values(request, "buyer_id"),
        "date_field": request.GET.get("date_field", "callback").strip() or "callback",
        "date_from": request.GET.get("date_from", "").strip(),
        "date_to": request.GET.get("date_to", "").strip(),
    }
    supplied_by_permission = {
        "rid": selected["search"],
        "branch": selected["branch"],
        "sub_branch": selected["sub_branch"],
        "shift": selected["shift"],
        "user": selected["user"],
        "status": selected["status"],
        "country": selected["country"],
        "client": selected["client"],
        "buyer": selected["buyer_id"],
        "date": selected["date_from"] or selected["date_to"],
    }
    for filter_name, value in supplied_by_permission.items():
        if value and not filters_access.get(filter_name, False):
            raise PermissionDenied(
                f"Your account cannot use the {filter_name.replace('_', ' ')} filter."
            )
    if selected["date_field"] not in {"initiated", "callback"}:
        selected["date_field"] = "callback"
    return selected


def _term_report_base_queryset():
    return SurveyAttempt.objects.select_related(
        "survey__integration__client",
        "survey__client",
        "platform_user__employee_profile__organization_unit__parent__parent",
    ).filter(status__in=UNSUCCESSFUL_ATTEMPT_STATUSES)


def _term_report_datetime(value, label):
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        raise PermissionDenied(f"{label} must use a valid date and time.")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _filtered_term_report_queryset(request, filters_access):
    selected = _term_report_filter_state(request, filters_access)
    queryset = _term_report_base_queryset()
    search = selected["search"]
    if search:
        queryset = queryset.filter(
            Q(rid__icontains=search)
            | Q(pid__icontains=search)
            | Q(prescreener_uid__icontains=search)
            | Q(provider_profile_uid__icontains=search)
            | Q(survey__local_id__icontains=search)
            | Q(survey__source_key__icontains=search)
            | Q(survey__buyer_id__icontains=search)
            | Q(survey__client__name__icontains=search)
            | Q(platform_user__username__icontains=search)
            | Q(platform_user__first_name__icontains=search)
            | Q(platform_user__last_name__icontains=search)
            | Q(platform_user__email__icontains=search)
            | Q(initiation_ip__icontains=search)
            | Q(callback_ip__icontains=search)
        )

    filter_data = {
        name: ",".join(selected[name])
        for name in ("branch", "sub_branch", "shift", "user", "status", "country", "client", "buyer_id")
        if selected[name]
    }
    queryset = SurveyAttemptFilter(filter_data, queryset=queryset).qs
    lower = _term_report_datetime(selected["date_from"], "From date and time")
    upper = _term_report_datetime(selected["date_to"], "To date and time")
    if lower and upper and lower > upper:
        raise PermissionDenied("From date and time cannot be after To date and time.")
    date_column = "initiated_at" if selected["date_field"] == "initiated" else "callback_at"
    if lower:
        queryset = queryset.filter(**{f"{date_column}__gte": lower})
    if upper:
        queryset = queryset.filter(**{f"{date_column}__lte": upper})
    return queryset, selected


def _term_report_options(base_queryset, user):
    hierarchy = user_hit_filter_options(user)
    return {
        **hierarchy,
        "countries": list(
            base_queryset.exclude(survey__country_code="")
            .values("survey__country_code", "survey__country")
            .distinct().order_by("survey__country_code")
        ),
        "clients": list(
            base_queryset.filter(survey__client__isnull=False)
            .values("survey__client_id", "survey__client__name")
            .distinct().order_by("survey__client__name")
        ),
        "buyers": list(
            base_queryset.exclude(survey__buyer_id="")
            .values("survey__client_id", "survey__buyer_id")
            .distinct().order_by("survey__buyer_id")
        ),
    }


def _latest_callback_first(queryset):
    """Apply the same null-safe PostgreSQL ordering to report pages and exports."""

    return queryset.order_by(
        F("callback_at").desc(nulls_last=True),
        F("initiated_at").desc(),
    )


@function_permission_required("termination_reasons.view")
def termination_reasons_page(request):
    codes = effective_permission_codes(request.user)
    filters_access = _component_access(codes, TERM_REASON_FILTER_PERMISSIONS)
    columns = _permitted_columns(codes, TERM_REASON_COLUMN_PERMISSIONS)
    queryset, selected = _filtered_term_report_queryset(request, filters_access)
    detail_rid = (request.GET.get("detail") or request.GET.get("rid") or "").strip()
    detail_attempt = None
    detail_outcome = None
    lookup_error = ""

    if detail_rid and "termination_reasons.action.details" not in codes:
        raise PermissionDenied("Your account cannot open outcome details.")

    base_queryset = _term_report_base_queryset()
    filter_options = _term_report_options(base_queryset, request.user)

    summary = queryset.aggregate(
        total=Count("id"),
        terminated=Count("id", filter=Q(status=SurveyAttempt.Status.TERMINATED)),
        quota=Count("id", filter=Q(status=SurveyAttempt.Status.OVER_QUOTA)),
        quality=Count("id", filter=Q(status=SurveyAttempt.Status.QUALITY_TERMINATED)),
    )
    page_obj = Paginator(_latest_callback_first(queryset), 20).get_page(
        request.GET.get("page", 1)
    )
    for row in page_obj.object_list:
        row.reason_outcome = provider_outcome(row)
        row.reason_status_label = UNSUCCESSFUL_STATUS_LABELS.get(row.status, row.get_status_display())

    if detail_rid:
        if len(detail_rid) != 10 or not detail_rid.isalnum():
            lookup_error = "The requested RID must contain exactly 10 letters and numbers."
        else:
            detail_attempt = base_queryset.filter(rid=detail_rid).first()
            if detail_attempt is None:
                non_terminal_attempt = SurveyAttempt.objects.select_related(
                    "survey__integration__client", "survey__client", "platform_user"
                ).filter(rid=detail_rid).first()
                if non_terminal_attempt:
                    lookup_error = (
                        f"This RID is currently {non_terminal_attempt.get_status_display().lower()}; "
                        "provider outcome details become available after a final unsuccessful status."
                    )
        if not lookup_error and detail_attempt is None:
            lookup_error = "No survey attempt was found for this RID."
        elif detail_attempt:
            detail_attempt.reason_status_label = UNSUCCESSFUL_STATUS_LABELS.get(
                detail_attempt.status, detail_attempt.get_status_display()
            )
            detail_outcome = provider_outcome(detail_attempt)
            integration = detail_attempt.survey.integration if detail_attempt.survey.integration_id else None
            provider_code = (integration.provider_code if integration else "innovatemr").lower()
            supports_lookup = provider_code == "innovatemr" or bool(
                integration and integration.transaction_endpoint_template
            )
            if (
                supports_lookup
                and "termination_reasons.action.refresh" in codes
                and (not detail_outcome["status"] or not detail_outcome["reason"])
            ):
                try:
                    _refresh_provider_outcome(detail_attempt, integration)
                    detail_outcome = provider_outcome(detail_attempt)
                except (InnovateMRAPIError, ValueError) as exc:
                    provider_label = integration.client.name if integration else "InnovateMR"
                    lookup_error = (
                        f"The attempt was found, but {provider_label} could not return its detailed "
                        f"transaction yet: {exc}"
                    )

    link_params = request.GET.copy()
    for parameter in ("detail", "rid"):
        link_params.pop(parameter, None)
    detail_query = link_params.urlencode()
    page_params = link_params.copy()
    page_params.pop("page", None)
    page_query = page_params.urlencode()

    return render(request, "surveys/termination_reasons.html", {
        "active_page": "termination-reasons",
        "selected": selected,
        "search_query": selected["search"],
        "client_options": filter_options["clients"],
        "term_reason_clients": filter_options["clients"],
        "term_branches": filter_options["branches"],
        "term_sub_branches": filter_options["sub_branches"],
        "term_shifts": filter_options["shifts"],
        "term_users": filter_options["users"],
        "term_countries": filter_options["countries"],
        "term_buyers": filter_options["buyers"],
        "attempt_statuses": list(UNSUCCESSFUL_STATUS_LABELS.items()),
        "summary": summary,
        "page_obj": page_obj,
        "reason_columns": columns,
        "reason_column_count": max(1, len(columns)),
        "reason_filters": filters_access,
        "reason_cards": _permitted_columns(codes, TERM_REASON_CARD_PERMISSIONS),
        "can_paginate_reasons": "termination_reasons.control.pagination" in codes,
        "can_view_reason_details": "termination_reasons.action.details" in codes,
        "detail_attempt": detail_attempt,
        "detail_outcome": detail_outcome,
        "detail_query": detail_query,
        "page_query": page_query,
        "lookup_error": lookup_error,
        "can_refresh_reasons": "termination_reasons.action.refresh" in codes,
        "can_export_reasons": "termination_reasons.export" in codes,
        "reason_fields": _component_access(codes, TERM_REASON_FIELD_PERMISSIONS),
    })


@function_permission_required("termination_reasons.export")
def termination_reasons_export(request):
    """Export the exact filtered Term Reports result set with both status layers."""

    codes = effective_permission_codes(request.user)
    filters_access = _component_access(codes, TERM_REASON_FILTER_PERMISSIONS)
    queryset, _selected = _filtered_term_report_queryset(request, filters_access)
    queryset = _latest_callback_first(queryset)

    headers = [
        "RID", "PID", "UID", "Project ID", "Client survey ID", "Client", "Provider",
        "Buyer ID", "Country", "Respondent", "Email", "Entry IP", "Exit IP",
        "Platform status", "Provider status", "Term reason", "Term category",
        "Status source", "Started at", "Ended at", "LOI (minutes)",
    ]
    widths = [
        15, 13, 22, 19, 20, 22, 18, 17, 13, 22, 30, 17, 17, 20, 27, 44, 22,
        20, 24, 24, 15,
    ]

    def rows():
        for attempt in queryset.iterator(chunk_size=500):
            outcome = provider_outcome(attempt)
            survey = attempt.survey
            client = survey.client or (survey.integration.client if survey.integration_id else None)
            provider = survey.integration.provider_code if survey.integration_id else "innovatemr"
            respondent = ""
            email = ""
            if attempt.platform_user_id:
                respondent = attempt.platform_user.get_full_name() or attempt.platform_user.username
                email = attempt.platform_user.email
            ended_at = attempt.callback_at or attempt.last_callback_at or attempt.initiated_at
            yield [
                attempt.rid,
                attempt.pid,
                attempt.provider_profile_uid or attempt.prescreener_uid or "",
                survey.local_id,
                survey.source_key,
                client.name if client else survey.company_name,
                provider,
                survey.buyer_id,
                survey.country_code or survey.country,
                respondent,
                email,
                attempt.initiation_ip or "",
                attempt.callback_ip or "",
                UNSUCCESSFUL_STATUS_LABELS.get(attempt.status, attempt.get_status_display()),
                outcome.get("status") or "Not supplied",
                outcome.get("reason") or "",
                outcome.get("category") or "",
                attempt.status_source,
                _excel_datetime(attempt.initiated_at),
                _excel_datetime(ended_at),
                round(attempt.loi_seconds / 60, 2) if attempt.loi_seconds is not None else "",
            ]

    local_now = timezone.localtime()
    return build_excel_response(
        f"term-reports-{local_now:%Y%m%d-%H%M%S}-IST.xlsx",
        [ExcelSheet("Term Reports", headers, rows(), widths)],
    )


def workspace_home(request):
    if not request.user.is_authenticated:
        if getattr(settings, "OFFERWALL_ENABLED", False):
            from offerwall.views import landing

            return landing(request)
        from django.contrib.auth.views import redirect_to_login
        return redirect_to_login(request.get_full_path())
    codes = effective_permission_codes(request.user)

    def allowed(code):
        return (
            request.user.is_active and request.user.is_superuser
        ) or code in codes

    if allowed("projects.view"):
        return HttpResponseRedirect(reverse("projects"))
    if allowed("dashboard.view"):
        return HttpResponseRedirect(reverse("dashboard"))
    if allowed("attempts.view"):
        return HttpResponseRedirect(reverse("traffic-reports"))
    if allowed("termination_reasons.view"):
        return HttpResponseRedirect(reverse("termination-reasons"))
    if allowed("user_hits.view"):
        return HttpResponseRedirect(reverse("user-hits"))
    if allowed("prescreener_data.view"):
        return HttpResponseRedirect(reverse("prescreened-data"))
    if any(allowed(code) for code in ("vendors.view", "vendors.manage", "allocations.view", "allocations.manage")):
        return HttpResponseRedirect(reverse("vendor-management"))
    if any(allowed(code) for code in ("access.manage", "users.view", "users.create", "roles.view", "roles.create")):
        return HttpResponseRedirect(reverse("access-control"))
    from django.core.exceptions import PermissionDenied
    raise PermissionDenied("No workspace page is assigned to this account.")


def _qualifying_option_values(question):
    """Return provider-approved option IDs, translating RFG gender IDs for UI."""

    raw = question.raw_data or {}
    if "targeting_choices" not in raw:
        return None
    allowed = {str(value) for value in raw.get("targeting_choices") or []}
    if not allowed:
        return None
    if question.key == "RFG_GENDER":
        return {
            "M" if value == "1" else "F" if value == "2" else value
            for value in allowed
        }
    return allowed


def _rfg_profile_dimension(question):
    """Return the mandatory profile dimension represented by an RFG row."""

    key = re.sub(r"[^a-z0-9]+", " ", str(question.key or "").lower()).strip()
    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        clean_rfg_display_text(question.text or "").lower(),
    ).strip()
    combined = f"{key} {text}"
    if re.search(r"\b(gender|sex)\b", combined):
        return "gender"
    if re.search(r"\b(date of birth|birthday|dob|age)\b", combined):
        return "age"
    if re.search(r"\b(postal code|postcode|zip code|zipcode|zip)\b", combined):
        return "postal"
    return ""


def _rfg_alias_allowed_values(question, dimension):
    """Translate targeting choices to the mandatory profile control values."""

    choices = {
        str(value) for value in (question.raw_data or {}).get("targeting_choices") or []
    }
    if dimension == "gender":
        return {
            "M" if value == "1" else "F" if value == "2" else value
            for value in choices
        }
    return choices


def _rfg_alias_upstream_values(alias, dimension, values):
    """Map one displayed profile answer back to a hidden RFG targeting code."""

    if dimension != "gender" or not values:
        return list(values)
    selected = str(values[0]).upper()
    wanted_label = "male" if selected in {"M", "1"} else "female"
    for option in alias.options or []:
        label = clean_rfg_display_text(option.get("OptionText") or "").lower().strip()
        if label == wanted_label:
            option_id = option.get("OptionId")
            if option_id not in (None, ""):
                return [str(option_id)]
    return ["1" if wanted_label == "male" else "2"]


def _prescreener_questions(survey, submitted_data=None, *, qualifying_options_only=True):
    """Prepare provider targeting rows as safe, responsive form controls and hints."""

    prepared = []
    provider_code = (
        survey.integration.provider_code
        if survey.integration_id else "innovatemr"
    )
    question_rows = list(survey.targeting_questions.all())
    if provider_code == "cint" and not question_rows:
        # Some open Cint opportunities genuinely have no qualifications. We
        # still need a minimal reusable profile, so collect age and gender as
        # platform-only answers. Empty question IDs/upstream values guarantee
        # these controls are never appended to the signed Cint entry URL.
        question_rows = [
            SimpleNamespace(
                pk="platform_profile_age",
                question_id="",
                key="AGE",
                text="What is your age?",
                question_type="Numeric",
                category="Required profile",
                options=[],
                raw_data={
                    "platform_only": True,
                    "targeting_age_ranges": [{"min": 13, "max": 120}],
                },
            ),
            SimpleNamespace(
                pk="platform_profile_gender",
                question_id="",
                key="GENDER",
                text="What is your gender?",
                question_type="Single Punch",
                category="Required profile",
                options=[
                    {"OptionId": "male", "OptionText": "Male"},
                    {"OptionId": "female", "OptionText": "Female"},
                ],
                raw_data={"platform_only": True},
            ),
        ]
    profile_aliases = {}
    aliased_question_ids = set()
    if provider_code == "rfg":
        required = {}
        for question in question_rows:
            dimension = _rfg_profile_dimension(question)
            is_required = (
                str(question.category or "").strip().lower() == "required profile"
                or str(question.key or "").upper()
                in {"RFG_BIRTHDAY", "RFG_GENDER", "RFG_POSTAL_CODE"}
            )
            if dimension and is_required:
                required[dimension] = question
        for question in question_rows:
            dimension = _rfg_profile_dimension(question)
            primary = required.get(dimension)
            if primary and primary.pk != question.pk:
                profile_aliases.setdefault(primary.pk, []).append(question)
                aliased_question_ids.add(question.pk)

    for question in question_rows:
        if question.pk in aliased_question_ids:
            continue
        display_text = clean_rfg_display_text(question.text or question.key)
        lowered_type = question.question_type.lower()
        normalized_key = str(question.key or "").upper()
        normalized_text = display_text.lower()
        is_dob_question = (
            normalized_key in {"DOB", "BIRTHDAY", "RFG_BIRTHDAY"}
            or "date of birth" in normalized_text
            or "birthday" in normalized_text
        )
        is_age_question = (
            normalized_key == "AGE"
            or ("your age" in normalized_text and not is_dob_question)
        )
        is_postal_question = (
            normalized_key in {"ZIP", "ZIP_CODE", "ZIPCODES", "POSTAL_CODE"}
            or "zipcode" in normalized_text
            or "zip code" in normalized_text
            or "postal code" in normalized_text
        )
        options = []
        age_ranges = []
        allowed_values = _qualifying_option_values(question)
        dimension = _rfg_profile_dimension(question) if provider_code == "rfg" else ""
        alias_allowed_sets = [
            _rfg_alias_allowed_values(alias, dimension)
            for alias in profile_aliases.get(question.pk, [])
            if (alias.raw_data or {}).get("targeting_choices")
        ]
        for alias_allowed in alias_allowed_sets:
            allowed_values = (
                set(alias_allowed)
                if allowed_values is None
                else set(allowed_values).intersection(alias_allowed)
            )
        for option in question.options:
            if not isinstance(option, dict):
                value = str(option).strip()
                if not value:
                    continue
                if qualifying_options_only and allowed_values and value not in allowed_values:
                    continue
                options.append({"value": value, "label": value})
                age_span = re.fullmatch(
                    r"(\d{1,3})\s*(?:-|\u2013|to)\s*(\d{1,3})",
                    value,
                    re.IGNORECASE,
                )
                if age_span:
                    start, end = int(age_span.group(1)), int(age_span.group(2))
                    if 0 <= start <= end <= 125:
                        age_ranges.append({"ageStart": start, "ageEnd": end})
                continue
            option_id = option.get("OptionId")
            if option.get("ageStart") is not None:
                label = f"{option.get('ageStart')}–{option.get('ageEnd')}"
                age_ranges.append(option)
            else:
                label = clean_rfg_display_text(
                    option.get("OptionText") or str(option_id or "Option")
                )
            value = str(option_id if option_id is not None else label)
            if qualifying_options_only and allowed_values and value not in allowed_values:
                continue
            options.append({"value": value, "label": label})
        if is_dob_question or is_age_question:
            for item in (question.raw_data or {}).get("targeting_age_ranges") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    age_ranges.append({
                        "ageStart": int(item["min"]),
                        "ageEnd": int(item["max"]),
                    })
                except (KeyError, TypeError, ValueError):
                    continue
            for alias in profile_aliases.get(question.pk, []):
                for item in (alias.raw_data or {}).get("targeting_age_ranges") or []:
                    if not isinstance(item, dict):
                        continue
                    try:
                        age_ranges.append({
                            "ageStart": int(item.get("min", item.get("ageStart"))),
                            "ageEnd": int(item.get("max", item.get("ageEnd"))),
                        })
                    except (TypeError, ValueError):
                        continue
        if (is_dob_question or is_age_question) and not age_ranges and allowed_values:
            # Compatibility for Cint targeting stored before explicit age
            # ranges were normalized. Prefer the provider's visible labels so
            # grouped precodes such as "18-24" are not mistaken for ages 1/2.
            for option in options:
                label = str(option["label"]).strip()
                single_age = re.fullmatch(r"\d{1,3}", label)
                age_span = re.fullmatch(
                    r"(\d{1,3})\s*(?:-|\u2013|to)\s*(\d{1,3})",
                    label,
                    re.IGNORECASE,
                )
                if single_age:
                    start = end = int(label)
                elif age_span:
                    start, end = (int(age_span.group(1)), int(age_span.group(2)))
                else:
                    continue
                if 0 <= start <= end <= 125:
                    age_ranges.append({"ageStart": start, "ageEnd": end})
        if age_ranges:
            merged_age_ranges = []
            for item in sorted(age_ranges, key=lambda row: int(row["ageStart"])):
                start, end = int(item["ageStart"]), int(item["ageEnd"])
                if merged_age_ranges and start <= merged_age_ranges[-1]["ageEnd"] + 1:
                    merged_age_ranges[-1]["ageEnd"] = max(
                        merged_age_ranges[-1]["ageEnd"], end
                    )
                else:
                    merged_age_ranges.append({"ageStart": start, "ageEnd": end})
            age_ranges = merged_age_ranges
        if is_dob_question:
            input_kind = "date_mask"
            display_text = "What is your date of birth?"
        elif is_age_question:
            input_kind = "number"
            display_text = "What is your age?"
        elif is_postal_question:
            # Postal codes are identifiers, not numbers: leading zeroes and
            # country-specific letters must survive exactly as entered.
            input_kind = "text"
        elif "date" in lowered_type:
            input_kind = "date_mask"
        elif "multi" in lowered_type:
            input_kind = "checkbox"
        elif "single" in lowered_type and options:
            input_kind = "radio"
        elif options:
            # Providers sometimes label derived/boolean qualifications as
            # ``Dummy`` (for example Region or Mobile Device) even though
            # they supply a closed option list. A fixed list must never fall
            # back to a free-text field: one respondent value is selected.
            input_kind = "radio"
        elif question.key.upper() == "AGE" or "numeric" in lowered_type:
            input_kind = "number"
        else:
            input_kind = "text"
        field_name = f"question_{question.pk}"
        selected_values = submitted_data.getlist(field_name) if submitted_data is not None else []
        current_value = selected_values[0] if selected_values else ""
        if input_kind == "date_mask" and current_value:
            try:
                current_value = date.fromisoformat(current_value).strftime("%d-%m-%Y")
            except ValueError:
                pass
        for option in options:
            option["selected"] = option["value"] in selected_values
        min_value = min((int(item["ageStart"]) for item in age_ranges), default=None)
        max_value = max((int(item["ageEnd"]) for item in age_ranges), default=None)
        age_range_labels = [
            f"{int(item['ageStart'])}\u2013{int(item['ageEnd'])}"
            for item in age_ranges
        ]
        qualifying_labels = [
            option["label"] for option in options
            if not allowed_values or option["value"] in allowed_values
        ]
        if allowed_values and qualifying_options_only and not qualifying_labels:
            qualifying_labels = sorted(allowed_values)
        if qualifying_labels:
            answer_word = "answer" if len(qualifying_labels) == 1 else "answers"
            qualifying_answer_note = (
                f"Qualifying {answer_word}: {', '.join(qualifying_labels)}"
                if len(qualifying_labels) <= 6
                else f"{len(qualifying_labels)} provider-approved answers are shown."
            )
        else:
            qualifying_answer_note = ""
        prepared.append({
            "model": question,
            "profile_dimension": dimension,
            "aliases": profile_aliases.get(question.pk, []),
            "display_text": display_text,
            "field_name": field_name,
            "input_kind": input_kind,
            "type_label": (
                "Date of birth" if is_dob_question
                else "Age" if is_age_question
                else "Postal code" if is_postal_question
                else "Date" if input_kind == "date_mask"
                else (question.question_type or "Question")
            ),
            "options": options,
            "current_value": current_value,
            "min_value": min_value,
            "max_value": max_value,
            "input_label": (
                "Age" if is_age_question
                else "ZIP / postal code" if is_postal_question
                else "Your answer"
            ),
            "placeholder": (
                "Enter your age" if is_age_question
                else "Enter your ZIP / postal code" if is_postal_question
                else "Enter a number"
            ),
            "is_dob_question": is_dob_question,
            "is_postal_question": is_postal_question,
            "allowed_values": sorted(allowed_values or []),
            "qualifying_options_only": bool(
                qualifying_options_only and allowed_values
            ),
            "targeting_note": (
                f"Qualifying age: {', '.join(age_range_labels)}"
                if (is_age_question or is_dob_question) and age_range_labels
                else "Only answers accepted by this survey are shown."
                if provider_code == "rfg" and qualifying_options_only and allowed_values
                else "Enter a ZIP/postal code accepted by this survey."
                if is_postal_question and qualifying_options_only and allowed_values
                else qualifying_answer_note
                if qualifying_options_only and allowed_values else ""
            ),
        })
    return prepared


def _collect_prescreener_answers(request, survey):
    """Validate submitted controls and produce vault plus provider answer values."""

    answers = {}
    errors = []
    provider_code = (
        survey.integration.provider_code
        if survey.integration_id else "innovatemr"
    )
    for prepared in _prescreener_questions(
        survey, qualifying_options_only=False
    ):
        question = prepared["model"]
        if prepared["input_kind"] == "date_mask":
            raw_date = request.POST.get(prepared["field_name"], "").strip()
            try:
                parts = raw_date.split("-")
                if len(parts) != 3:
                    raise ValueError
                if len(parts[0]) == 4:
                    year, month, day = parts
                else:
                    day, month, year = parts
                normalized_date = date(int(year), int(month), int(day)).isoformat()
            except (TypeError, ValueError):
                errors.append(
                    f"Enter a valid date in DD-MM-YYYY format for: {prepared['display_text']}"
                )
                continue
            values = [normalized_date]
        else:
            values = [value.strip() for value in request.POST.getlist(prepared["field_name"]) if value.strip()]
        if not values:
            errors.append(f"Please answer: {prepared['display_text']}")
            continue

        valid_options = {item["value"] for item in prepared["options"]}
        upstream_values = values.copy()
        if prepared["input_kind"] in {"radio", "checkbox"}:
            invalid = [value for value in values if value not in valid_options]
            if invalid:
                errors.append(f"Invalid answer for: {prepared['display_text']}")
                continue
        elif prepared["input_kind"] == "number":
            try:
                numeric_value = int(values[0])
            except ValueError:
                errors.append(f"Enter a valid number for: {prepared['display_text']}")
                continue
            if provider_code == "innovatemr":
                # Innovate expects the actual open-ended age/number. The
                # targeting OptionId describes an accepted range, not the
                # respondent's profile value.
                upstream_values = [str(numeric_value)]
            else:
                matched = [
                    str(option.get("OptionId"))
                    for option in question.options
                    if isinstance(option, dict)
                    and option.get("ageStart") is not None
                    and int(option["ageStart"]) <= numeric_value <= int(option["ageEnd"])
                    and option.get("OptionId") is not None
                ]
                upstream_values = matched or [str(numeric_value)]
        elif prepared.get("is_postal_question") and prepared.get("allowed_values"):
            accepted = {str(value).casefold() for value in prepared["allowed_values"]}
            if values[0].casefold() not in accepted:
                errors.append(
                    f"Enter a ZIP/postal code accepted by this survey for: {prepared['display_text']}"
                )
                continue

        platform_only = bool((question.raw_data or {}).get("platform_only"))
        if platform_only:
            upstream_values = []

        answers[str(question.pk)] = {
            "question_id": question.question_id,
            "question_key": question.key,
            "question_text": prepared["display_text"],
            "question_type": question.question_type,
            "question_category": question.category,
            "values": values,
            "upstream_values": upstream_values,
            "platform_only": platform_only,
        }
        for alias in prepared.get("aliases", []):
            alias_upstream_values = _rfg_alias_upstream_values(
                alias,
                prepared.get("profile_dimension", ""),
                upstream_values,
            )
            answers[str(alias.pk)] = {
                "question_id": alias.question_id,
                "question_key": alias.key,
                "question_text": clean_rfg_display_text(alias.text or alias.key),
                "values": values,
                "upstream_values": alias_upstream_values,
                "profile_alias": question.key,
            }
    return answers, errors


def _invalid_survey_link(request, message="This link is invalid or is no longer available.", status_code=400):
    """Render the generic public error without leaking which validation failed."""

    return render(request, "surveys/flow_error.html", {
        "title": "Invalid survey link",
        "message": message,
    }, status=status_code)


def _has_exact_query(request, expected_names):
    """Reject duplicated or client-injected start-link parameters."""
    return set(request.GET.keys()) == set(expected_names) and all(
        len(request.GET.getlist(name)) == 1 for name in expected_names
    )


def _rfg_result_url(rid, result):
    """Build the local RFG browser-result URL for an attempt RID."""

    return f"{reverse('rfg-result')}?{urlencode({'rid': rid, 'result': result})}"


def _finish_local_rfg_attempt(attempt, answers, request, *, result, reason):
    """Atomically finalize a strict-mode RFG rejection before provider redirect."""

    now = timezone.now()
    with transaction.atomic():
        locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        if locked.status != SurveyAttempt.Status.INITIATED:
            return locked
        client_data = get_request_client_data(request)
        locked.answers = operational_answer_value(answers)
        locked.submitted_at = now
        locked.callback_at = now
        locked.last_callback_at = now
        locked.callback_ip = get_request_ip(request) or locked.initiation_ip
        locked.exit_user_agent = client_data.get("user_agent", "")
        locked.exit_browser = client_data.get("browser", "")
        locked.exit_device = client_data.get("device", "")
        locked.exit_os = client_data.get("os", "")
        locked.exit_client_data = client_data
        locked.status = RFG_STATUS_MAP[result]
        locked.status_source = "local_prescreener"
        locked.loi_seconds = locked.calculate_loi_seconds(now)
        locked.upstream_transaction_data = {
            **(locked.upstream_transaction_data or {}),
            "rfg_local_outcome": {"result": result, "local_reason": reason},
        }
        locked.save(update_fields=[
            "answers", "submitted_at", "callback_at", "last_callback_at", "callback_ip",
            "exit_user_agent", "exit_browser", "exit_device", "exit_os", "exit_client_data",
            "status", "status_source", "loi_seconds", "upstream_transaction_data", "updated_at",
        ])
        finalize_attempt_capacity(locked)
    return locked


def _finish_wrong_target_country_attempt(attempt, request, location):
    """Record a local S4 before any prescreener question or provider redirect."""

    now = timezone.now()
    expected = survey_target_country_code(attempt.survey)
    actual = str((location or {}).get("country_code") or "").upper()
    vault_answers = wrong_target_country_answers(attempt, location)
    if settings.PRESCREENER_VAULT_ENABLED:
        try:
            capture_prescreener_submission(attempt, vault_answers, submitted_at=now)
        except PrescreenerVaultError:
            # Country enforcement must still protect the provider contract. The
            # failed vault write remains visible in logs for operational retry.
            logger.exception(
                "Wrong-target-country vault capture failed for rid=%s", attempt.rid
            )

    with transaction.atomic():
        locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        if locked.status != SurveyAttempt.Status.INITIATED:
            return locked
        client_data = {
            **get_request_client_data(request),
            **geolocation_client_data(location),
        }
        locked.answers = operational_answer_value(vault_answers)
        locked.submitted_at = now
        locked.callback_at = now
        locked.last_callback_at = now
        locked.callback_ip = get_request_ip(request) or locked.initiation_ip
        locked.exit_user_agent = client_data.get("user_agent", "")
        locked.exit_browser = client_data.get("browser", "")
        locked.exit_device = client_data.get("device", "")
        locked.exit_os = client_data.get("os", "")
        locked.exit_client_data = client_data
        locked.status = SurveyAttempt.Status.QUALITY_TERMINATED
        locked.status_source = "local_country_guard"
        locked.loi_seconds = locked.calculate_loi_seconds(now)
        locked.upstream_transaction_data = {
            **(locked.upstream_transaction_data or {}),
            "local_country_guard": {
                "status": "Wrong target country",
                "reason": "Wrong target country",
                "expected_country": expected,
                "detected_country": actual,
                "geo_source": str((location or {}).get("source") or ""),
            },
        }
        locked.save(update_fields=[
            "answers", "submitted_at", "callback_at", "last_callback_at", "callback_ip",
            "exit_user_agent", "exit_browser", "exit_device", "exit_os", "exit_client_data",
            "status", "status_source", "loi_seconds", "upstream_transaction_data", "updated_at",
        ])
        finalize_attempt_capacity(locked)
    return locked


def _mark_attempt_redirected(attempt, answers, outbound_url):
    """Atomically claim one initiated attempt for its provider redirect.

    Provider adapters can touch the separate prescreener-vault database while
    constructing a URL (for example, Cint assigns and audits an email identity).
    Those operations must finish *before* the main-database write so a slow
    vault operation never holds a ``SurveyAttempt`` row lock.  The conditional
    update is a compare-and-swap: only the first concurrent form submission can
    move the attempt from initiated to redirected.
    """

    now = timezone.now()
    updated = SurveyAttempt.objects.filter(
        pk=attempt.pk,
        status=SurveyAttempt.Status.INITIATED,
    ).update(
        answers=operational_answer_value(answers),
        submitted_at=now,
        redirected_at=now,
        outbound_url=outbound_url,
        status=SurveyAttempt.Status.REDIRECTED,
        updated_at=now,
    )
    return bool(updated)


@require_http_methods(["GET"])
def supplier_survey_start(request):
    """Claim a supplier respondent using a signed, API-key-scoped entry URL."""

    if not _has_exact_query(request, {"key", "survey", "token", "pid"}):
        return _invalid_survey_link(request)
    public_id = request.GET.get("key", "").strip()
    survey_local_id = request.GET.get("survey", "").strip()
    token = request.GET.get("token", "").strip()
    supplier_pid = request.GET.get("pid", "").strip()
    if not supplier_pid or len(supplier_pid) > 160 or any(ord(char) < 32 for char in supplier_pid):
        return _invalid_survey_link(request, "A valid supplier respondent ID is required.")

    api_key = VendorAPIKey.objects.select_related(
        "vendor", "vendor__employee_profile", "vendor__vendor_commercial_profile"
    ).filter(public_id=public_id).first()
    now = timezone.now()
    commercial = getattr(getattr(api_key, "vendor", None), "vendor_commercial_profile", None)
    if (
        not api_key or not api_key.is_active or api_key.revoked_at
        or (api_key.expires_at and api_key.expires_at <= now)
        or not api_key.vendor.is_active or not commercial or not commercial.is_active
        or not commercial.api_access_enabled
    ):
        return _invalid_survey_link(request, "This supplier link is inactive.", status_code=403)
    from vendors.supplier_delivery import verify_supplier_entry_signature

    if not verify_supplier_entry_signature(api_key, survey_local_id, token):
        return _invalid_survey_link(request, "This supplier link signature is invalid.", status_code=403)
    survey = scope_surveys_for_api_key(
        scope_surveys_for_user(
            Survey.objects.select_related("integration", "client"), api_key.vendor
        ),
        api_key,
    ).filter(local_id=survey_local_id, status=Survey.Status.LIVE).first()
    if not survey:
        return _invalid_survey_link(request, "This project is not assigned to the supplier.", status_code=404)
    entry_location = resolve_entry_geolocation(request)
    entry_client_data = {
        **get_request_client_data(request),
        **geolocation_client_data(entry_location),
    }
    try:
        with transaction.atomic():
            allocation_context = resolve_vendor_survey_context(
                api_key.vendor, survey, require_capacity=False, for_update=True
            )
            attempt = create_attempt(
                survey,
                api_key.vendor,
                get_request_ip(request),
                client_data=entry_client_data,
                supplier_respondent_id=supplier_pid,
            )
            reserve_attempt_capacity(
                attempt,
                allocation_context.survey_allocation,
                client_allocation=allocation_context.client_allocation,
            )
    except AllocationUnavailable as exc:
        return _invalid_survey_link(request, str(exc), status_code=409)
    return HttpResponseRedirect(f"{reverse('survey-start')}?rid={quote(attempt.rid)}")


@require_http_methods(["GET", "POST"])
def survey_start(request):
    """Validate copied links, run the prescreener and redirect one claimed attempt.

    Initial GET creates the immutable RID/UID journey; canonical GET renders its
    questions; POST writes the vault, applies provider checks and records exactly
    one outbound redirect. See ``docs/developer-handbook.md`` for the call graph.
    """

    if request.method == "GET" and not request.GET.get("rid"):
        has_pid_parameter = "pid" in request.GET
        required_params = {"surveyId", "supplierCode", "userId", "code"}
        if has_pid_parameter:
            required_params.add("pid")
        if not _has_exact_query(request, required_params):
            return _invalid_survey_link(request)

        survey_id = request.GET.get("surveyId", "").strip()
        supplier_code = request.GET.get("supplierCode", "").strip()
        internal_code = request.GET.get("code", "").strip()
        user_id = request.GET.get("userId", "").strip()
        platform_pid = request.GET.get("pid", "").strip()
        if (
            not survey_id
            or len(survey_id) > 160
            or not user_id.isdigit()
            or not internal_code.isdigit()
            or len(internal_code) != 14
            or (
                has_pid_parameter
                and (not platform_pid.isalnum() or not 6 <= len(platform_pid) <= 9)
            )
        ):
            return _invalid_survey_link(request)

        platform_user = get_user_model().objects.filter(pk=int(user_id), is_active=True).first()
        if (
            platform_user is None
            or not has_function_access(platform_user, "projects.view")
            or not has_function_access(platform_user, "survey_links.copy")
        ):
            return _invalid_survey_link(request)

        survey = scope_surveys_for_user(
            Survey.objects.select_related("integration", "client"), platform_user
        ).filter(
            source_key=survey_id, local_id=internal_code, status=Survey.Status.LIVE
        ).first()
        if survey is None:
            return _invalid_survey_link(request)
        provider_code = (
            survey.integration.provider_code if survey.integration_id else ""
        )
        is_rfg = provider_code == "rfg"
        supports_lazy_entry_link = provider_code in {"rfg", "cint"}
        if not survey.entry_link and not supports_lazy_entry_link:
            return _invalid_survey_link(request)
        expected_supplier_code = settings.PUBLIC_SUPPLIER_CODE
        if supplier_code != expected_supplier_code:
            return _invalid_survey_link(request)

        detail_provider = None
        try:
            if provider_code == "cint":
                try:
                    detail_provider = get_provider(survey.integration)
                    redirect_ready = detail_provider.redirect_contract_is_current(survey)
                except Exception:
                    logger.exception(
                        "Could not validate Cint supplier-link state survey=%s", survey.pk
                    )
                    redirect_ready = False
                if not redirect_ready:
                    try:
                        from .tasks import sync_cint_redirects_task

                        sync_cint_redirects_task.delay(survey.integration_id, batch_size=25)
                    except Exception:
                        logger.exception(
                            "Could not queue Cint supplier-link repair survey=%s", survey.pk
                        )
                    return _invalid_survey_link(
                        request,
                        "This survey link is still being secured. Please try again shortly.",
                        status_code=503,
                    )

            stale = survey.inventory_source != Survey.InventorySource.MANUAL and (
                survey.targeting_synced_at is None or (
                    survey.source_modified_at
                    and survey.targeting_synced_at < survey.source_modified_at
                )
            )
            if provider_code in {"biobrain", "voqall"} and survey.targeting_questions.filter(
                Q(text="") | Q(key__regex=r"^\d+$")
            ).exists():
                stale = True
            if supports_lazy_entry_link:
                stale = stale or not survey.entry_link
            if is_rfg:
                stale = stale or not survey.entry_link or not survey.targeting_questions.filter(
                    raw_data__adapter_version__in=[2, 3]
                ).exists()
            targeting_warning = ""
            if stale:
                try:
                    if detail_provider is not None:
                        detail_provider.refresh_details(survey)
                    elif survey.integration_id and has_provider(survey.integration.provider_code):
                        with managed_provider(get_provider(survey.integration)) as provider:
                            provider.refresh_details(survey)
                    else:
                        with managed_provider(
                            InnovateMRClient(integration=survey.integration)
                        ) as client:
                            replace_survey_targeting(client, survey)
                except Exception:
                    logger.exception(
                        "Provider detail hydration failed for survey=%s integration=%s",
                        survey.pk,
                        survey.integration_id,
                    )
                    if not survey.entry_link:
                        return _invalid_survey_link(
                            request,
                            "The provider entry link is temporarily unavailable. Please try again shortly.",
                            status_code=503,
                        )
                    if not survey.targeting_questions.exists():
                        targeting_warning = "Pre-screening criteria are temporarily unavailable. You can still continue."
        finally:
            close_provider(detail_provider)
        if not survey.entry_link:
            return _invalid_survey_link(
                request,
                "The provider entry link is temporarily unavailable. Please try again shortly.",
                status_code=503,
            )
        entry_location = resolve_entry_geolocation(request)
        entry_client_data = {
            **get_request_client_data(request),
            **geolocation_client_data(entry_location),
        }
        try:
            with transaction.atomic():
                allocation_context = resolve_vendor_survey_context(
                    platform_user,
                    survey,
                    require_capacity=True,
                    for_update=True,
                )
                attempt = create_attempt(
                    survey,
                    platform_user,
                    get_request_ip(request),
                    client_data=entry_client_data,
                    pid=platform_pid or None,
                )
                if allocation_context:
                    reserve_attempt_capacity(
                        attempt,
                        allocation_context.survey_allocation,
                        client_allocation=allocation_context.client_allocation,
                    )
        except AllocationUnavailable as exc:
            return _invalid_survey_link(request, str(exc), status_code=409)
        if targeting_warning:
            request.session[f"attempt_warning_{attempt.rid}"] = targeting_warning
        return HttpResponseRedirect(f"{reverse('survey-start')}?rid={quote(attempt.rid)}")

    if request.method == "GET" and not _has_exact_query(request, {"rid"}):
        return _invalid_survey_link(request)

    rid = (request.GET.get("rid", "") if request.method == "GET" else request.POST.get("rid", "")).strip()
    if len(rid) != 10 or not rid.isalnum():
        return _invalid_survey_link(request)
    attempt = SurveyAttempt.objects.select_related(
        "survey", "survey__integration", "platform_user"
    ).filter(rid=rid).first()
    if attempt is None or attempt.platform_user is None or not attempt.platform_user.is_active:
        return _invalid_survey_link(request, status_code=404)
    attempt = backfill_attempt_entry_audit(attempt, request)

    entry_location = {
        "ip": attempt.initiation_ip or "",
        "country_code": (attempt.entry_client_data or {}).get("geo_country_code", ""),
        "country": (attempt.entry_client_data or {}).get("geo_country", ""),
        "postal_code": (attempt.entry_client_data or {}).get("geo_postal_code", ""),
        "source": (attempt.entry_client_data or {}).get("geo_source", ""),
    }
    if not entry_location["country_code"] and request.method == "GET":
        entry_location = resolve_entry_geolocation(request)
        geo_updates = geolocation_client_data(entry_location)
        if geo_updates:
            merged_client_data = {**(attempt.entry_client_data or {}), **geo_updates}
            SurveyAttempt.objects.filter(pk=attempt.pk).update(entry_client_data=merged_client_data)
            attempt.entry_client_data = merged_client_data
    if (
        attempt.status == SurveyAttempt.Status.INITIATED
        and is_wrong_target_country(attempt.survey, entry_location)
    ):
        attempt = _finish_wrong_target_country_attempt(attempt, request, entry_location)
        return HttpResponseRedirect(
            f"{reverse('survey-status')}?{urlencode({'status': '4', 'rid': attempt.rid})}"
        )

    if request.method == "POST":
        # A browser retry after a successful submission must not call the
        # provider or allocate another cross-database respondent identity.
        if attempt.status != SurveyAttempt.Status.INITIATED:
            return HttpResponseRedirect(
                f"{reverse('survey-start')}?rid={quote(attempt.rid)}"
            )
        answers, errors = _collect_prescreener_answers(request, attempt.survey)
        if not errors:
            provider = None
            try:
                prescreener_uid = ensure_attempt_prescreener_uid(attempt)
                provider = (
                    get_provider(attempt.survey.integration)
                    if attempt.survey.integration_id
                    and has_provider(attempt.survey.integration.provider_code)
                    else None
                )
                if provider and attempt.survey.integration.provider_code == "rfg":
                    eligible, reason = provider.validate_prescreener(attempt.survey, answers)
                    if not eligible:
                        if settings.PRESCREENER_VAULT_ENABLED:
                            capture_prescreener_submission(
                                attempt,
                                answers_with_entry_postal_code(attempt, answers),
                            )
                        _finish_local_rfg_attempt(
                            attempt, answers, request, result="7", reason=reason
                        )
                        return HttpResponseRedirect(_rfg_result_url(attempt.rid, "7"))

                # Select reuse before writing a new vault row. A reused
                # respondent keeps the original vault RID + UID pair and only
                # that row's Visits counter increases. The SurveyAttempt RID is
                # still unique so callbacks cannot collide between journeys.
                reuse_event = maybe_assign_reusable_profile(attempt, answers)
                if settings.PRESCREENER_VAULT_ENABLED and reuse_event is None:
                    capture_prescreener_submission(
                        attempt,
                        answers_with_entry_postal_code(attempt, answers),
                    )

                if provider and attempt.survey.integration.provider_code == "rfg":
                    if provider.duplicate_check(
                        attempt.survey,
                        attempt,
                        get_request_ip(request) or attempt.initiation_ip,
                        request.POST.get("rfg_fingerprint", "0"),
                    ):
                        _finish_local_rfg_attempt(
                            attempt,
                            answers,
                            request,
                            result="8",
                            reason="This respondent has already attempted this survey or survey group.",
                        )
                        return HttpResponseRedirect(_rfg_result_url(attempt.rid, "8"))
                if not errors:
                    # URL construction may use the vault DB. Keep it outside a
                    # main-DB row lock, then claim the redirect with one short,
                    # conditional UPDATE to avoid MySQL 1205/1213 failures.
                    outbound_url = (
                        provider.build_outbound_url(attempt.survey, attempt, answers)
                        if provider
                        else build_outbound_url(
                            attempt.survey.entry_link,
                            attempt.rid,
                            answers,
                            prescreener_uid=prescreener_uid,
                            rid_parameter=(
                                attempt.survey.manual_rid_parameter
                                if attempt.survey.inventory_source
                                == Survey.InventorySource.MANUAL
                                else ""
                            ),
                        )
                    )
                    if not _mark_attempt_redirected(attempt, answers, outbound_url):
                        return HttpResponseRedirect(
                            f"{reverse('survey-start')}?rid={quote(attempt.rid)}"
                        )
                    return HttpResponseRedirect(outbound_url)
            except Exception as exc:
                if isinstance(exc, PrescreenerVaultError):
                    logger.exception("Prescreener vault capture failed for rid=%s", attempt.rid)
                    detail = (
                        "No real respondent email is currently available. Please contact the workspace administrator."
                        if isinstance(exc, CintEmailPoolExhausted)
                        else "Secure prescreener storage is temporarily unavailable. Please submit again shortly."
                    )
                else:
                    logger.exception(
                        "Survey provider continuation failed for rid=%s provider=%s",
                        attempt.rid,
                        attempt.survey.integration.provider_code
                        if attempt.survey.integration_id else "legacy",
                    )
                    detail = str(exc) if isinstance(exc, ProviderError) else "The upstream provider is temporarily unavailable."
                errors.append(f"Survey provider could not continue: {detail}")
            finally:
                close_provider(provider)
    else:
        errors = []

    if attempt.status != SurveyAttempt.Status.INITIATED:
        return render(request, "surveys/status.html", {
            "title": "Survey already initiated",
            "message": "This RID has already been used to enter the survey.",
            "tone": "info",
            "status_label": attempt.get_status_display(),
            "rid": attempt.rid,
            "ip_address": attempt.callback_ip or attempt.initiation_ip,
            "loi_seconds": attempt.loi_seconds,
            "attempt_found": True,
        })

    return render(request, "surveys/prescreener.html", {
        "attempt": attempt,
        "survey": attempt.survey,
        "questions": _prescreener_questions(attempt.survey, request.POST if request.method == "POST" else None),
        "errors": errors,
        "warning": request.session.pop(f"attempt_warning_{attempt.rid}", ""),
        "is_rfg": bool(
            attempt.survey.integration_id
            and attempt.survey.integration.provider_code == "rfg"
        ),
    })


STATUS_PAGES = {
    "1": {"title": "Thank you for participating!", "message": "Your survey response has been completed successfully.", "tone": "success"},
    "2": {"title": "Survey ended", "message": "The survey provider ended this attempt before it could be completed.", "tone": "neutral"},
    "3": {"title": "Quota already filled", "message": "The required quota was filled before your response could be completed.", "tone": "warning"},
    "4": {"title": "Quality check unsuccessful", "message": "This response did not pass the survey's quality checks.", "tone": "danger"},
}


RFG_CALLBACK_IPS = {
    "15.222.163.99", "3.97.223.177", "3.97.28.227", "3.230.105.121",
    "52.21.20.32", "52.45.41.61",
}


def _rfg_attempt_from_request(request):
    """Resolve RFG TID first, then the UID echoed in RFG's ``rid`` field.

    Provider parameter names never replace platform identity. A successful UID
    lookup returns its SurveyAttempt row, whose immutable 10-character ``rid``
    remains the canonical journey key in callbacks, reports and status logic.
    """

    base = SurveyAttempt.objects.select_related("survey__integration").filter(
        survey__integration__provider_code="rfg"
    )
    matched_attempt = None
    for name in ("tid", "TID", "trackId"):
        value = str(request.GET.get(name) or "").strip()
        if value:
            attempt = base.filter(rid=value).first()
            if attempt:
                if matched_attempt and matched_attempt.pk != attempt.pk:
                    return None
                matched_attempt = attempt
    for name in ("rid", "RID", "pid", "PID", "qsid", "QSID"):
        value = str(request.GET.get(name) or "").strip()
        if value:
            if matched_attempt and value in {
                matched_attempt.rid,
                matched_attempt.pid,
                matched_attempt.prescreener_uid,
                matched_attempt.provider_profile_uid,
            }:
                continue
            attempt = base.filter(
                Q(rid=value) | Q(prescreener_uid=value) | Q(provider_profile_uid=value)
            ).order_by("-initiated_at").first()
            if attempt:
                if matched_attempt and matched_attempt.pk != attempt.pk:
                    return None
                matched_attempt = attempt
    return matched_attempt


@require_http_methods(["GET"])
def rfg_result(request):
    attempt = _rfg_attempt_from_request(request)
    if not attempt:
        return _invalid_survey_link(
            request, "This RFG result link is invalid.", status_code=404
        )

    browser_parameters = dict(request.GET.items())
    now = timezone.now()
    client_data = get_request_client_data(request)
    with transaction.atomic():
        locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        locked.last_callback_at = now
        locked.exit_user_agent = client_data.get("user_agent", "")
        locked.exit_browser = client_data.get("browser", "")
        locked.exit_device = client_data.get("device", "")
        locked.exit_os = client_data.get("os", "")
        locked.exit_client_data = client_data
        locked.upstream_transaction_data = {
            **(locked.upstream_transaction_data or {}),
            "rfg_browser_return": browser_parameters,
        }
        locked.save(update_fields=[
            "last_callback_at", "exit_user_agent", "exit_browser", "exit_device", "exit_os",
            "exit_client_data", "upstream_transaction_data", "updated_at",
        ])
        attempt = locked

    stored = attempt.upstream_transaction_data or {}
    local_parameters = stored.get("rfg_local_outcome") or {}
    callback_parameters = stored.get("rfg_callback") or {}
    outcome_parameters = (
        callback_parameters if attempt.is_verified else local_parameters or browser_parameters
    )
    outcome = describe_rfg_outcome(outcome_parameters, attempt=attempt)
    return render(request, "surveys/rfg_result.html", {
        "attempt": attempt,
        "outcome": outcome,
        "verified": bool(attempt.is_verified or attempt.status_source == "local_prescreener"),
        "verification_pending": bool(
            attempt.status_source != "local_prescreener" and not attempt.is_verified
        ),
    })


class RFGCallbackAPIView(APIView):
    """Receive RFG's server callback from documented RFG callback addresses."""

    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["RFG Callbacks"],
        summary="Receive a verified Research For Good result callback",
        description=(
            "Called by RFG after a respondent outcome. It updates the RID attempt, exit IP/time, "
            "LOI and allocation state. This is not a normal admin test endpoint: Swagger calls will "
            "normally receive 403 because only RFG's configured server IPs are trusted. Use the "
            "RFG callback preview endpoint to safely understand result/live codes without writing data."
        ),
        parameters=[
            OpenApiParameter("tid", OpenApiTypes.STR, required=False, description="Platform 10-character attempt RID echoed from RFG TID"),
            OpenApiParameter("rid", OpenApiTypes.STR, required=True, description="Persistent prescreener UID echoed from RFG RID; used to resolve the canonical platform RID"),
            OpenApiParameter("result", OpenApiTypes.STR, required=True, description="RFG result code"),
            OpenApiParameter("ruledOutBy", OpenApiTypes.STR, required=False, description="RFG termination reason"),
            OpenApiParameter("sesskey", OpenApiTypes.STR, required=False, description="RFG session identifier"),
            OpenApiParameter("liveP", OpenApiTypes.STR, required=False, description="RFG respondent journey bit field"),
            OpenApiParameter("liveS", OpenApiTypes.STR, required=False, description="RFG security detail code"),
            OpenApiParameter("liveI", OpenApiTypes.STR, required=False, description="RFG invalid-profile detail code"),
            OpenApiParameter("quotaThrottle", OpenApiTypes.STR, required=False, description="RFG quota throttle flag"),
        ],
        responses={200: RFGCallbackResponseSerializer},
    )
    def get(self, request):
        result = request.GET.get("result", "").strip()
        attempt = _rfg_attempt_from_request(request)
        if not attempt or result not in RFG_STATUS_MAP:
            return Response({"detail": "Unknown callback."}, status=status.HTTP_400_BAD_REQUEST)

        integration = attempt.survey.integration
        config = integration.config or {}
        if config.get("callback_security_mode", "ip") != "ip":
            return Response(
                {"detail": "Unsupported callback security mode."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        callback_ip = get_request_ip(request)
        allowed = set(config.get("callback_ip_allowlist") or RFG_CALLBACK_IPS)
        try:
            verified_ip = bool(callback_ip and str(ipaddress.ip_address(callback_ip)) in allowed)
        except ValueError:
            verified_ip = False
        if not verified_ip:
            return Response({"detail": "Callback source is not trusted."}, status=status.HTTP_403_FORBIDDEN)

        now = timezone.now()
        with transaction.atomic():
            locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
            locked.status = RFG_STATUS_MAP[result]
            locked.callback_at = locked.callback_at or now
            locked.last_callback_at = now
            locked.callback_ip = callback_ip
            locked.callback_count += 1
            locked.status_source = "rfg_callback"
            locked.is_verified = True
            locked.loi_seconds = locked.calculate_loi_seconds(now)
            locked.upstream_transaction_data = {
                **(locked.upstream_transaction_data or {}),
                "rfg_callback": dict(request.GET.items()),
                "rfg_outcome": describe_rfg_outcome(dict(request.GET.items())),
            }
            locked.save(update_fields=[
                "status", "callback_at", "last_callback_at", "callback_ip", "callback_count",
                "status_source", "is_verified", "loi_seconds", "upstream_transaction_data", "updated_at",
            ])
            finalize_attempt_capacity(locked)
        return Response({
            "ok": True,
            "rid": locked.rid,
            "status": locked.status,
        })


def _record_browser_result(attempt, status_code, request, *, source="browser_callback"):
    """Record the first browser outcome while keeping callback retries idempotent."""

    ip_address = get_request_ip(request)
    with transaction.atomic():
        attempt = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        now = timezone.now()
        exit_client_data = get_request_client_data(request)
        if attempt.callback_at is None:
            attempt.callback_at = now
            attempt.callback_ip = ip_address
            attempt.loi_seconds = attempt.calculate_loi_seconds(now)
            attempt.status = status_code
            attempt.exit_user_agent = exit_client_data.get("user_agent", "")
            attempt.exit_browser = exit_client_data.get("browser", "")
            attempt.exit_device = exit_client_data.get("device", "")
            attempt.exit_os = exit_client_data.get("os", "")
            attempt.exit_client_data = exit_client_data
            attempt.status_source = source
        attempt.last_callback_at = now
        attempt.callback_count += 1
        attempt.save(update_fields=[
            "callback_at", "callback_ip", "loi_seconds", "status", "exit_user_agent", "exit_browser",
            "exit_device", "exit_os", "exit_client_data", "status_source", "last_callback_at",
            "callback_count", "updated_at"
        ])
        finalize_attempt_capacity(attempt)
    return attempt


@require_http_methods(["GET"])
def biobrain_survey_return(request, status_code):
    """Accept Voqall's return URL using only ``vq_token`` as our canonical RID."""

    status_code = str(status_code)
    query_status = request.GET.get("status_id", "").strip()
    rid = (request.GET.get("vq_token") or request.GET.get("VQ_TOKEN") or "").strip()
    if (
        status_code not in STATUS_PAGES
        or (query_status and query_status != status_code)
        or len(rid) != 10
        or not rid.isalnum()
    ):
        return render(request, "surveys/flow_error.html", {
            "title": "Invalid Bio Brain callback",
            "message": "A matching status (1–4) and valid RID token are required.",
        }, status=400)

    attempt = SurveyAttempt.objects.filter(
        rid=rid,
        survey__integration__provider_code="biobrain",
    ).first()
    if attempt is None:
        return render(request, "surveys/flow_error.html", {
            "title": "Survey attempt not found",
            "message": "This RID could not be attached to a Bio Brain survey attempt.",
        }, status=404)

    attempt = _record_browser_result(
        attempt,
        status_code,
        request,
        source="biobrain_browser_callback",
    )
    recorded_status = attempt.status if attempt.status in STATUS_PAGES else status_code
    result_base_url = settings.PUBLIC_RESULT_BASE_URL or settings.PUBLIC_APP_BASE_URL
    if not result_base_url:
        result_base_url = request.build_absolute_uri("/").rstrip("/")
    return HttpResponseRedirect(
        f"{result_base_url}/survey?{urlencode({'status': recorded_status, 'rid': attempt.rid})}"
    )


def _enligne_rid_from_identifier(value):
    """Resolve either a bare RID or Enligne's ``KANIK_<RID>`` LID value."""

    identifier = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9]{10}", identifier):
        return identifier
    match = re.search(r"(?:^|[_-])([A-Za-z0-9]{10})$", identifier)
    return match.group(1) if match else ""


@csrf_exempt
@require_http_methods(["GET", "POST"])
def enligne_survey_postback(request):
    """Record Enligne's server-to-server status hit without a browser redirect."""

    params = request.GET.copy()
    params.update(request.POST)
    status_code = str(params.get("status") or params.get("status_id") or "").strip()
    if status_code not in STATUS_PAGES:
        return JsonResponse({"ok": False, "error": "invalid_status"}, status=400)

    identifier = next((
        str(params.get(name) or "").strip()
        for name in ("rid", "RID", "aff_sub", "AFF_SUB", "trackId", "trackid", "lid", "LID")
        if params.get(name)
    ), "")
    rid = _enligne_rid_from_identifier(identifier)
    if not rid:
        return JsonResponse({"ok": False, "error": "invalid_lid"}, status=400)

    attempt = SurveyAttempt.objects.filter(
        rid=rid,
        survey__integration__provider_code="enligne",
    ).first()
    if attempt is None:
        return JsonResponse({"ok": False, "error": "attempt_not_found"}, status=404)

    attempt, first_verified_result = _record_enligne_s2s_result(
        attempt,
        status_code,
        request,
        params.dict(),
    )

    return JsonResponse({
        "ok": True,
        "rid": attempt.rid,
        "status": attempt.status,
        "duplicate": not first_verified_result,
    })


def _record_enligne_s2s_result(attempt, status_code, request, payload):
    """Persist one verified Enligne result received on either callback route."""

    ip_address = get_request_ip(request)
    with transaction.atomic():
        attempt = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        now = timezone.now()
        first_verified_result = not attempt.is_verified
        if first_verified_result:
            if attempt.callback_at is None:
                attempt.callback_at = now
                attempt.loi_seconds = attempt.calculate_loi_seconds(now)
            attempt.status = status_code
            attempt.callback_ip = ip_address
            attempt.status_source = "enligne_s2s_postback"
            attempt.is_verified = True
            transaction_data = dict(attempt.upstream_transaction_data or {})
            transaction_data["enligne_postback"] = payload
            attempt.upstream_transaction_data = transaction_data
        attempt.last_callback_at = now
        attempt.callback_count += 1
        attempt.save(update_fields=[
            "status", "callback_at", "last_callback_at", "callback_ip", "callback_count",
            "status_source", "is_verified", "loi_seconds", "upstream_transaction_data", "updated_at",
        ])
        finalize_attempt_capacity(attempt)
    return attempt, first_verified_result


INNOVATEMR_FINAL_SOURCES = {
    "innovatemr_redirect_hash",
    "innovatemr_hash_rejected",
    "innovatemr_status_rejected",
}


def _attempt_provider_code(attempt):
    if attempt.survey.integration_id:
        return attempt.survey.integration.provider_code
    if attempt.survey.client_id:
        return attempt.survey.client.provider_code
    return ""


def _record_innovatemr_result(
    attempt,
    upstream_status,
    request,
    *,
    hash_valid,
    rejection_reason="",
):
    """Persist the first authoritative InnovateMR decision and finalize capacity.

    An invalid first callback is terminal and cannot later be upgraded. Likewise,
    an invalid replay cannot downgrade an already verified completion.
    """

    with transaction.atomic():
        locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        now = timezone.now()
        already_final = locked.is_verified or locked.status_source in INNOVATEMR_FINAL_SOURCES
        first_authoritative_result = not already_final
        mapped_status = INNOVATEMR_STATUS_MAP.get(str(upstream_status or ""))
        if first_authoritative_result:
            if hash_valid and mapped_status:
                locked.status = mapped_status
                locked.status_source = "innovatemr_redirect_hash"
                locked.is_verified = True
            elif hash_valid:
                locked.status = SurveyAttempt.Status.QUALITY_TERMINATED
                locked.status_source = "innovatemr_status_rejected"
                locked.is_verified = True
                rejection_reason = rejection_reason or "unsupported_status"
            else:
                locked.status = SurveyAttempt.Status.QUALITY_TERMINATED
                locked.status_source = "innovatemr_hash_rejected"
                locked.is_verified = False
                rejection_reason = rejection_reason or "hash_mismatch"

            exit_client_data = get_request_client_data(request)
            if locked.callback_at is None:
                locked.callback_at = now
                locked.loi_seconds = locked.calculate_loi_seconds(now)
            locked.callback_ip = get_request_ip(request)
            locked.exit_user_agent = exit_client_data.get("user_agent", "")
            locked.exit_browser = exit_client_data.get("browser", "")
            locked.exit_device = exit_client_data.get("device", "")
            locked.exit_os = exit_client_data.get("os", "")
            locked.exit_client_data = exit_client_data

        locked.last_callback_at = now
        locked.callback_count += 1
        audit = dict(locked.upstream_transaction_data or {})
        audit["innovatemr_redirect"] = {
            "upstream_status": str(upstream_status or ""),
            "hash_valid": bool(hash_valid),
            "algorithm": "hmac-sha1-hex",
            "rejection_reason": rejection_reason,
            "duplicate": not first_authoritative_result,
        }
        locked.upstream_transaction_data = audit
        locked.save(update_fields=[
            "status", "callback_at", "last_callback_at", "callback_ip", "callback_count",
            "status_source", "is_verified", "loi_seconds", "exit_user_agent", "exit_browser",
            "exit_device", "exit_os", "exit_client_data", "upstream_transaction_data", "updated_at",
        ])
        finalize_attempt_capacity(locked)
    return locked, first_authoritative_result


def _record_gms_result(attempt, upstream_status, request):
    """Persist GMS's first unsigned status redirect as the final outcome."""

    with transaction.atomic():
        locked = SurveyAttempt.objects.select_for_update().get(pk=attempt.pk)
        now = timezone.now()
        first_authoritative_result = not (
            locked.is_verified or locked.status_source == "gms_redirect"
        )
        if first_authoritative_result:
            locked.status = upstream_status
            locked.status_source = "gms_redirect"
            locked.is_verified = True
            exit_client_data = get_request_client_data(request)
            if locked.callback_at is None:
                locked.callback_at = now
                locked.loi_seconds = locked.calculate_loi_seconds(now)
            locked.callback_ip = get_request_ip(request)
            locked.exit_user_agent = exit_client_data.get("user_agent", "")
            locked.exit_browser = exit_client_data.get("browser", "")
            locked.exit_device = exit_client_data.get("device", "")
            locked.exit_os = exit_client_data.get("os", "")
            locked.exit_client_data = exit_client_data

        locked.last_callback_at = now
        locked.callback_count += 1
        audit = dict(locked.upstream_transaction_data or {})
        audit["gms_redirect"] = {
            "upstream_status": str(upstream_status),
            "duplicate": not first_authoritative_result,
        }
        locked.upstream_transaction_data = audit
        locked.save(update_fields=[
            "status", "callback_at", "last_callback_at", "callback_ip", "callback_count",
            "status_source", "is_verified", "loi_seconds", "exit_user_agent", "exit_browser",
            "exit_device", "exit_os", "exit_client_data", "upstream_transaction_data", "updated_at",
        ])
        finalize_attempt_capacity(locked)
    return locked, first_authoritative_result


def _respondent_result_redirect(attempt):
    from vendors.supplier_delivery import supplier_outcome_redirect

    supplier_url = supplier_outcome_redirect(attempt)
    if supplier_url:
        response = HttpResponseRedirect(supplier_url)
        response["Cache-Control"] = "no-store"
        return response
    if getattr(settings, "OFFERWALL_ENABLED", False):
        from offerwall.services import result_url_for_attempt

        offerwall_url = result_url_for_attempt(attempt)
        if offerwall_url:
            response = HttpResponseRedirect(offerwall_url)
            response["Cache-Control"] = "no-store"
            return response
    result_base_url = settings.PUBLIC_RESULT_BASE_URL or settings.PUBLIC_APP_BASE_URL
    if not result_base_url:
        result_base_url = "https://www.rmwinsights.com"
    response = HttpResponseRedirect(
        f"{result_base_url}/survey?{urlencode({'status': attempt.status, 'rid': attempt.rid})}"
    )
    response["Cache-Control"] = "no-store"
    return response


@require_http_methods(["GET"])
def innovatemr_callback(request):
    """Verify InnovateMR's signed redirect before recording any completion."""

    secret = settings.INNOVATEMR_CALLBACK_HASH_SECRET
    public_url = settings.INNOVATEMR_CALLBACK_PUBLIC_URL
    if not secret or not public_url:
        return render(request, "surveys/flow_error.html", {
            "title": "Callback temporarily unavailable",
            "message": "The secure survey callback is not configured.",
        }, status=503)

    pid_values = request.GET.getlist("pid")
    status_values = request.GET.getlist("status")
    hash_values = request.GET.getlist("hash")
    pid = pid_values[0].strip() if len(pid_values) == 1 else ""
    upstream_status = status_values[0].strip() if len(status_values) == 1 else ""
    received_hash = hash_values[0].strip() if len(hash_values) == 1 else ""

    if len(pid) != 10 or not pid.isalnum():
        return render(request, "surveys/flow_error.html", {
            "title": "Survey attempt not found",
            "message": "This callback could not be attached to a survey attempt.",
        }, status=404)

    attempt = SurveyAttempt.objects.select_related(
        "survey__integration", "survey__client"
    ).filter(rid=pid).filter(
        Q(survey__integration__provider_code="innovatemr")
        | Q(survey__integration__isnull=True, survey__client__provider_code="innovatemr")
    ).first()
    if attempt is None:
        return render(request, "surveys/flow_error.html", {
            "title": "Survey attempt not found",
            "message": "This callback could not be attached to an InnovateMR survey attempt.",
        }, status=404)

    valid_shape = (
        len(pid_values) == 1
        and len(status_values) == 1
        and len(hash_values) == 1
    )
    hash_valid = False
    rejection_reason = "invalid_parameters" if not valid_shape else ""
    if valid_shape:
        try:
            hash_valid = verify_callback_hash(
                secret=secret,
                public_url=public_url,
                raw_query=request.META.get("QUERY_STRING", ""),
                received_hash=received_hash,
            )
        except (CallbackConfigurationError, ValueError):
            hash_valid = False
            rejection_reason = "invalid_hash_contract"
    if not hash_valid and not rejection_reason:
        rejection_reason = "hash_mismatch"

    attempt, _ = _record_innovatemr_result(
        attempt,
        upstream_status,
        request,
        hash_valid=hash_valid,
        rejection_reason=rejection_reason,
    )
    return _respondent_result_redirect(attempt)


@require_http_methods(["GET"])
def gms_callback(request):
    """Record one of GMS's four status redirects without hash or reason fields."""

    pid_values = request.GET.getlist("pid")
    status_values = request.GET.getlist("status")
    pid = pid_values[0].strip() if len(pid_values) == 1 else ""
    upstream_status = status_values[0].strip() if len(status_values) == 1 else ""
    if (
        set(request.GET.keys()) != {"pid", "status"}
        or len(pid_values) != 1
        or len(status_values) != 1
        or upstream_status not in STATUS_PAGES
    ):
        return render(request, "surveys/flow_error.html", {
            "title": "Invalid GMS callback",
            "message": "Exactly one pid and one status (1–4) are required.",
        }, status=400)
    if len(pid) != 10 or not pid.isalnum():
        return render(request, "surveys/flow_error.html", {
            "title": "Survey attempt not found",
            "message": "This callback could not be attached to a survey attempt.",
        }, status=404)

    attempt = SurveyAttempt.objects.select_related(
        "survey__integration", "survey__client"
    ).filter(rid=pid).filter(
        Q(survey__integration__provider_code="gms")
        | Q(survey__client__provider_code="gms")
        | Q(survey__client__code__iexact="gms")
        | Q(survey__client__name__iexact="gms")
    ).first()
    if attempt is None:
        return render(request, "surveys/flow_error.html", {
            "title": "Survey attempt not found",
            "message": "This callback could not be attached to a GMS survey attempt.",
        }, status=404)

    attempt, _ = _record_gms_result(attempt, upstream_status, request)
    return _respondent_result_redirect(attempt)


@require_http_methods(["GET"])
def survey_status(request):
    status_code = request.GET.get("status", "").strip()
    enligne_identifier = (
        request.GET.get("aff_sub") or request.GET.get("AFF_SUB") or ""
    ).strip()
    callback_identifiers = status_identifiers_from_request(request)
    if enligne_identifier:
        enligne_rid = _enligne_rid_from_identifier(enligne_identifier)
        callback_identifiers = [
            value for value in [enligne_rid, *callback_identifiers] if value
        ]
    callback_identifier = callback_identifiers[0] if callback_identifiers else ""
    page = STATUS_PAGES.get(status_code)
    if page is None or not callback_identifier:
        return render(request, "surveys/flow_error.html", {
            "title": "Invalid survey status",
            "message": "A valid status (1–4) and tracking ID are required.",
        }, status=400)

    attempts = SurveyAttempt.objects.select_related("survey__integration", "survey__client")
    if enligne_identifier:
        attempt = attempts.filter(
            rid=callback_identifier,
            survey__integration__provider_code="enligne",
        ).first()
    else:
        attempt = attempts.filter(rid__in=callback_identifiers).first()
        if attempt is None:
            attempt = attempts.filter(pid__in=callback_identifiers).first()
        if attempt is None:
            attempt = attempts.filter(prescreener_uid__in=callback_identifiers).first()
        if attempt is None:
            attempt = attempts.filter(
                provider_profile_uid__in=callback_identifiers
            ).order_by("-initiated_at").first()
    canonical_rid = attempt.rid if attempt else callback_identifier
    provider_code = _attempt_provider_code(attempt) if attempt else ""
    ip_address = get_request_ip(request)
    if attempt and provider_code == "innovatemr":
        attempt, _ = _record_innovatemr_result(
            attempt,
            status_code,
            request,
            hash_valid=False,
            rejection_reason="unsigned_callback_endpoint",
        )
        return _respondent_result_redirect(attempt)
    if attempt and enligne_identifier:
        attempt, _ = _record_enligne_s2s_result(
            attempt,
            status_code,
            request,
            request.GET.dict(),
        )
        status_label = attempt.get_status_display()
    elif attempt:
        canonical_query = set(request.GET.keys()) == {"status", "pid"} and (
            request.GET.get("pid", "").strip() == attempt.pid
        )
        with transaction.atomic():
            attempt = SurveyAttempt.objects.select_related(
                "survey__integration"
            ).select_for_update().get(pk=attempt.pk)
            now = timezone.now()
            exit_client_data = get_request_client_data(request)
            first_callback = attempt.callback_at is None
            if first_callback:
                attempt.callback_at = now
                attempt.callback_ip = ip_address
                attempt.loi_seconds = attempt.calculate_loi_seconds(now)
                attempt.status = status_code
                attempt.exit_user_agent = exit_client_data.get("user_agent", "")
                attempt.exit_browser = exit_client_data.get("browser", "")
                attempt.exit_device = exit_client_data.get("device", "")
                attempt.exit_os = exit_client_data.get("os", "")
                attempt.exit_client_data = exit_client_data
                attempt.status_source = "browser_callback"
            update_fields = [
                "callback_at", "callback_ip", "loi_seconds", "status",
                "exit_user_agent", "exit_browser", "exit_device", "exit_os",
                "exit_client_data", "status_source",
            ]
            if first_callback or not canonical_query:
                attempt.last_callback_at = now
                attempt.callback_count += 1
                update_fields.extend(["last_callback_at", "callback_count"])
            if not canonical_query:
                callback_data = dict(request.GET.items())
                if "hash" in callback_data:
                    callback_data["hash"] = "[redacted]"
                audit_key = (
                    "rfg_browser_return" if provider_code == "rfg"
                    else "cint_browser_return" if provider_code == "cint"
                    else "browser_return"
                )
                audit = {
                    **(attempt.upstream_transaction_data or {}),
                    audit_key: callback_data,
                }
                if provider_code == "rfg":
                    audit["rfg_outcome"] = describe_rfg_outcome(
                        callback_data, attempt=attempt
                    )
                attempt.upstream_transaction_data = audit
                update_fields.append("upstream_transaction_data")
            attempt.save(update_fields=list(dict.fromkeys(update_fields + ["updated_at"])))
            finalize_attempt_capacity(attempt)
        status_label = attempt.get_status_display()
        if not canonical_query:
            clean_query = urlencode({"status": status_code, "pid": attempt.pid})
            return HttpResponseRedirect(f"{reverse('survey-status')}?{clean_query}")
    else:
        status_label = "Unknown attempt"

    if attempt and attempt.status in STATUS_PAGES:
        if getattr(settings, "OFFERWALL_ENABLED", False):
            from offerwall.services import result_url_for_attempt

            offerwall_url = result_url_for_attempt(attempt)
            if offerwall_url:
                response = HttpResponseRedirect(offerwall_url)
                response["Cache-Control"] = "no-store"
                return response
        from vendors.supplier_delivery import supplier_outcome_redirect

        supplier_url = supplier_outcome_redirect(attempt)
        if supplier_url:
            response = HttpResponseRedirect(supplier_url)
            response["Cache-Control"] = "no-store"
            return response

    return render(request, "surveys/status.html", {
        **page,
        "status_label": status_label,
        "rid": canonical_rid,
        "pid": attempt.pid if attempt else callback_identifier,
        "display_rid": provider_code == "rfg",
        "ip_address": ip_address,
        "loi_seconds": attempt.loi_seconds if attempt else None,
        "attempt_found": bool(attempt),
    }, status=200 if attempt else 404)


@extend_schema_view(
    list=extend_schema(
        tags=["Canonical qualification mappings"],
        summary="List stable internal qualification keys",
        description=(
            "Provider-neutral question and answer keys. External supplier integrations should use these "
            "keys instead of hard-coding InnovateMR, RFG or Cint IDs."
        ),
    ),
    retrieve=extend_schema(
        tags=["Canonical qualification mappings"],
        summary="Get one stable qualification definition",
    ),
)
class CanonicalQuestionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CanonicalQuestion.objects.filter(is_active=True).prefetch_related("options")
    serializer_class = CanonicalQuestionSerializer
    lookup_field = "code"
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["code", "label", "description"]
    ordering_fields = ["code", "label", "updated_at"]
    ordering = ["code"]


@extend_schema_view(
    list=extend_schema(
        tags=["Canonical qualification mappings"],
        summary="List provider-to-platform question mappings",
        description=(
            "Shows how each provider's country/language-specific question IDs and answer precodes map "
            "to stable platform keys. Filter with provider_code, country_code, language_code or canonical_key."
        ),
        parameters=[
            OpenApiParameter("provider_code", OpenApiTypes.STR),
            OpenApiParameter("country_code", OpenApiTypes.STR),
            OpenApiParameter("language_code", OpenApiTypes.STR),
            OpenApiParameter("country_language_id", OpenApiTypes.STR),
            OpenApiParameter("canonical_key", OpenApiTypes.STR),
        ],
    ),
)
class ProviderQuestionMappingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ProviderQuestionMapping.objects.filter(is_active=True).select_related(
        "canonical_question"
    ).prefetch_related("option_mappings__canonical_option")
    serializer_class = ProviderQuestionMappingSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = [
        "external_question_id", "external_question_key", "canonical_question__code",
        "canonical_question__label",
    ]
    ordering_fields = ["provider_code", "country_code", "language_code", "external_question_id"]
    ordering = ["provider_code", "country_code", "language_code", "external_question_id"]

    def get_queryset(self):
        queryset = super().get_queryset()
        exact_filters = {
            "provider_code": "provider_code__iexact",
            "country_code": "country_code__iexact",
            "language_code": "language_code__iexact",
            "country_language_id": "country_language_id",
            "canonical_key": "canonical_question__code",
        }
        for parameter, lookup in exact_filters.items():
            value = self.request.query_params.get(parameter)
            if value not in (None, ""):
                queryset = queryset.filter(**{lookup: value})
        return queryset


@extend_schema_view(
    list=extend_schema(
        tags=["Surveys"],
        summary="List synchronized surveys",
        description="Returns locally stored surveys using the requesting user's access scope.",
    ),
    retrieve=extend_schema(
        tags=["Surveys"],
        summary="Get one survey",
        description="Returns one project with normalized quota and targeting details.",
    ),
)
class SurveyViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Survey.objects.select_related("client", "integration").all()
    project_count_cache_enabled = True
    lookup_field = "local_id"
    filterset_class = SurveyFilter
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, NullsLastOrderingFilter]
    search_fields = ["local_id", "=source_key", "=source_id", "name", "company_name", "buyer_id", "survey_type", "country", "country_code", "job_category"]
    ordering_fields = ["source_modified_at", "source_created_at", "cpi", "sample_size", "completes", "created_at"]
    nulls_last_ordering_fields = {"source_modified_at", "source_created_at"}
    ordering = [
        F("source_modified_at").desc(nulls_last=True),
        F("created_at").desc(),
    ]
    permission_classes = [HasFunctionPermission]

    def get_queryset(self):
        inventory = super().get_queryset().filter(
            Q(integration__isnull=True) | Q(integration__is_active=True)
        )
        queryset = scope_surveys_for_user(inventory, self.request.user)
        queryset = scope_surveys_for_api_key(queryset, self.request.auth)
        queryset = annotate_survey_pricing_for_user(queryset, self.request.user)
        completed_attempts = (
            SurveyAttempt.objects.filter(
                survey_id=OuterRef("pk"),
                status=SurveyAttempt.Status.COMPLETED,
            )
            .values("survey_id")
            .annotate(total=Count("pk"))
            .values("total")[:1]
        )
        queryset = queryset.annotate(
            platform_completes=Coalesce(
                Subquery(completed_attempts, output_field=IntegerField()),
                Value(0),
            )
        )
        if self.action == "retrieve":
            queryset = queryset.prefetch_related("quotas", "targeting_questions")
        return queryset

    def get_required_function_permission(self):
        if self.action == "export":
            return "projects.export"
        return "survey_details.view" if self.action in {"retrieve", "quotas", "targeting"} else "projects.view"

    def filter_queryset(self, queryset):
        _enforce_query_permissions(self.request, {
            "projects.filter.search": ("search",),
            "projects.filter.country": ("country",),
            "projects.filter.status": ("status",),
            "projects.filter.client": ("company", "client_name"),
            "projects.filter.buyer": ("buyer_id",),
            "projects.filter.survey_type": ("survey_type",),
            "projects.filter.date": ("created_from", "created_to", "modified_from", "modified_to"),
        })
        cpi_ordering = self.request.query_params.get("ordering", "").lstrip("-") == "cpi"
        cpi_filtering = any(self.request.query_params.get(name) not in {None, ""} for name in ("min_cpi", "max_cpi"))
        if (cpi_ordering or cpi_filtering) and not has_function_access(self.request.user, "projects.filter.cpi"):
            raise PermissionDenied("Your account cannot filter or sort projects by CPI.")
        queryset = super().filter_queryset(queryset)
        if cpi_ordering:
            direction = "-" if self.request.query_params.get("ordering", "").startswith("-") else ""
            queryset = queryset.order_by(
                f"{direction}visible_cpi",
                F("source_modified_at").desc(nulls_last=True),
                F("created_at").desc(),
            )
        elif self.request.query_params.get("ordering", "") in {
            "source_modified_at",
            "-source_modified_at",
        }:
            descending = self.request.query_params["ordering"].startswith("-")
            modified_order = (
                F("source_modified_at").desc(nulls_last=True)
                if descending
                else F("source_modified_at").asc(nulls_last=True)
            )
            queryset = queryset.order_by(
                modified_order,
                F("created_at").desc(),
            )
        return queryset

    def get_serializer_class(self):
        return SurveyDetailSerializer if self.action == "retrieve" else SurveyListSerializer

    @extend_schema(
        tags=["Surveys"],
        summary="Export all filtered projects",
        description=(
            "Downloads an Excel workbook containing every survey matching the current Projects filters and "
            "ordering. Pagination is ignored and columns follow the requesting user's project permissions."
        ),
        parameters=[
            OpenApiParameter("search", OpenApiTypes.STR, description="Search project ID, survey ID, name, country or category."),
            OpenApiParameter("country", OpenApiTypes.STR, description="Comma-separated country codes."),
            OpenApiParameter("status", OpenApiTypes.STR, description="Comma-separated survey statuses."),
            OpenApiParameter("company", OpenApiTypes.STR, description="Comma-separated client/company names."),
            OpenApiParameter("buyer_id", OpenApiTypes.STR, description="Comma-separated buyer/sub-client IDs."),
            OpenApiParameter("survey_type", OpenApiTypes.STR, description="Comma-separated normalized audience types, for example B2B,B2C."),
            OpenApiParameter("created_from", OpenApiTypes.DATETIME, description="Source-created timestamp lower bound."),
            OpenApiParameter("created_to", OpenApiTypes.DATETIME, description="Source-created timestamp upper bound."),
            OpenApiParameter("modified_from", OpenApiTypes.DATETIME, description="Source-modified timestamp lower bound."),
            OpenApiParameter("modified_to", OpenApiTypes.DATETIME, description="Source-modified timestamp upper bound."),
            OpenApiParameter("min_cpi", OpenApiTypes.NUMBER, description="Minimum viewer-visible CPI after configured cuts, inclusive."),
            OpenApiParameter("max_cpi", OpenApiTypes.NUMBER, description="Maximum viewer-visible CPI after configured cuts, inclusive."),
            OpenApiParameter("ordering", OpenApiTypes.STR, description="Current Projects ordering, including viewer-visible cpi or -cpi."),
        ],
        responses={(200, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"): OpenApiTypes.BINARY},
    )
    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request, *args, **kwargs):
        if not has_function_access(request.user, "projects.view"):
            raise PermissionDenied("Project visibility is required before projects can be exported.")
        queryset = self.filter_queryset(self.get_queryset())
        columns = [column for column in _project_columns_for_user(request.user) if column != "actions"]
        local_now = timezone.localtime()
        headers, rows, widths = _survey_excel_rows(queryset, request, columns)
        return build_excel_response(
            f"projects-{local_now:%Y%m%d-%H%M%S}-IST.xlsx",
            [ExcelSheet("Projects", headers, rows, widths)],
        )

    @staticmethod
    def _refresh_if_stale(survey, detail_type):
        synced_at = survey.quota_synced_at if detail_type == "quotas" else survey.targeting_synced_at
        stale = synced_at is None or (
            survey.source_modified_at is not None and synced_at < survey.source_modified_at
        )
        if (
            survey.integration_id
            and survey.integration.provider_code == "cint"
            and synced_at is not None
            and synced_at < timezone.now() - timedelta(seconds=60)
        ):
            stale = True
        if stale:
            if survey.integration_id and has_provider(survey.integration.provider_code):
                with managed_provider(get_provider(survey.integration)) as provider:
                    provider.refresh_details(survey)
            else:
                refresh = replace_survey_quotas if detail_type == "quotas" else replace_survey_targeting
                with managed_provider(
                    InnovateMRClient(integration=survey.integration)
                ) as client:
                    refresh(client, survey)

    @extend_schema(
        tags=["Survey details"],
        summary="List a survey's quotas",
        description="Returns the most recently synchronized, provider-normalized quota data for this survey.",
        responses={200: SurveyQuotaSerializer(many=True)},
    )
    @action(detail=True, methods=["get"])
    def quotas(self, request, local_id=None):
        survey = self.get_object()
        try:
            self._refresh_if_stale(survey, "quotas")
        except (InnovateMRAPIError, ProviderError) as exc:
            if survey.quota_synced_at is None and not survey.quotas.exists():
                raise UpstreamUnavailable(str(exc)) from exc
        return Response(SurveyQuotaSerializer(survey.quotas.all(), many=True).data)

    @extend_schema(
        tags=["Survey details"],
        summary="List pre-screening questions and accepted answers",
        description="Returns provider-normalized pre-screening questions. Answer codes preserve the upstream provider mapping.",
        responses={200: TargetingQuestionSerializer(many=True)},
    )
    @action(detail=True, methods=["get"], url_path="targeting")
    def targeting(self, request, local_id=None):
        survey = self.get_object()
        try:
            self._refresh_if_stale(survey, "targeting")
        except (InnovateMRAPIError, ProviderError) as exc:
            if survey.targeting_synced_at is None and not survey.targeting_questions.exists():
                raise UpstreamUnavailable(str(exc)) from exc
        return Response(TargetingQuestionSerializer(survey.targeting_questions.all(), many=True).data)


class SyncTriggerView(APIView):
    permission_classes = [HasFunctionPermission]
    required_function_permission = "sync.run"
    @extend_schema(
        tags=["Synchronization"],
        summary="Start an InnovateMR inventory synchronization",
        description=(
            "By default queues the same Celery task that beat runs every minute. Use wait=true for operational testing to run in the HTTP process "
            "and receive counters immediately. The sync fetches both full and cursor-paged inventory, deduplicates by surveyId using modifiedDate, "
            "and refreshes quota/targeting only for new or changed surveys."
        ),
        parameters=[OpenApiParameter("wait", OpenApiTypes.BOOL, description="Run synchronously and return the completed run summary.")],
        request=None,
        responses={200: SyncTriggerResponseSerializer, 202: OpenApiTypes.OBJECT},
        examples=[OpenApiExample("Synchronous result", value={"run_id": 42, "status": "success", "created": 3, "updated": 8, "unchanged": 110, "closed": 2, "detail_failures": 0}, response_only=True)],
    )
    def post(self, request):
        wait = str(request.query_params.get("wait", "false")).lower() in {"1", "true", "yes"}
        if wait:
            try:
                summary = sync_surveys()
            except InnovateMRAPIError as exc:
                raise UpstreamUnavailable(str(exc)) from exc
            return Response(SyncTriggerResponseSerializer(summary.__dict__).data)
        task = sync_innovatemr_surveys_task.delay()
        return Response({"task_id": task.id, "status": "queued"}, status=status.HTTP_202_ACCEPTED)


class SyncRunViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SyncRun.objects.all()
    serializer_class = SyncRunSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["status"]
    ordering_fields = ["started_at", "finished_at", "created", "updated", "detail_failures"]
    ordering = ["-started_at"]
    permission_classes = [HasFunctionPermission]
    required_function_permission = "sync.view"

    @extend_schema(tags=["Synchronization"], summary="List synchronization audit runs")
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(tags=["Synchronization"], summary="Get one synchronization audit run")
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        tags=["Survey attempts"],
        summary="List respondent survey attempts",
        description=(
            "Staff-only audit data for initiated pre-screeners, redirects, callbacks, IPs, measured LOI, "
            "survey country and the CPI snapshot frozen when the respondent entered."
        ),
    ),
    retrieve=extend_schema(
        tags=["Survey attempts"],
        summary="Get one respondent attempt by RID",
        description="Staff-only detail including captured answers and outbound supplier URL.",
    ),
)
class SurveyAttemptViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SurveyAttemptSerializer
    permission_classes = [HasFunctionPermission]
    lookup_field = "rid"
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, NullsLastOrderingFilter]
    filterset_class = SurveyAttemptFilter
    search_fields = [
        "rid", "user_id", "survey__local_id", "=survey__source_key", "=survey__source_id", "survey__name", "survey__company_name",
        "platform_user__username", "platform_user__first_name", "platform_user__last_name", "platform_user__email",
        "initiation_ip", "callback_ip", "entry_browser", "entry_device", "entry_os",
    ]
    ordering_fields = ["initiated_at", "callback_at", "loi_seconds", "status"]
    nulls_last_ordering_fields = {"callback_at", "loi_seconds"}
    ordering = ["-initiated_at"]

    def _filtered_summary(self, queryset):
        completed_filter = Q(status=SurveyAttempt.Status.COMPLETED)
        survey_termination_filter = Q(status=SurveyAttempt.Status.TERMINATED) & ~Q(
            status_source="local_prescreener"
        )
        summary = queryset.aggregate(
            total=Count("id"),
            initiated=Count("id", filter=Q(status__in=[SurveyAttempt.Status.INITIATED, SurveyAttempt.Status.REDIRECTED])),
            completed=Count("id", filter=completed_filter),
            terminated=Count("id", filter=Q(status=SurveyAttempt.Status.TERMINATED)),
            survey_terminated=Count("id", filter=survey_termination_filter),
            over_quota=Count("id", filter=Q(status=SurveyAttempt.Status.OVER_QUOTA)),
            security_terminated=Count("id", filter=Q(status=SurveyAttempt.Status.QUALITY_TERMINATED)),
            desktop=Count("id", filter=completed_filter & Q(entry_device__icontains="desktop")),
            mobile=Count("id", filter=completed_filter & (Q(entry_device__icontains="mobile") | Q(entry_device__icontains="phone"))),
            tablet=Count("id", filter=completed_filter & (Q(entry_device__icontains="tablet") | Q(entry_device__iexact="tab"))),
            total_revenue=Sum("source_cpi_snapshot", filter=completed_filter, default=Decimal("0.00")),
            supplier_revenue=Sum(
                Coalesce("payable_cpi_snapshot", "source_cpi_snapshot"),
                filter=completed_filter,
                default=Decimal("0.00"),
            ),
            revenue_currency=Max("cpi_currency_snapshot", filter=completed_filter),
        )
        completed = summary["completed"]
        ir_denominator = completed + summary["survey_terminated"]
        classified = summary["desktop"] + summary["mobile"] + summary["tablet"]
        summary["total_revenue"] = visible_amount_for_user(
            self.request.user, summary["total_revenue"]
        )
        card_access = _component_access(
            effective_permission_codes(self.request.user), STUDY_CARD_PERMISSIONS
        )
        visible = lambda card, value: value if card_access[card] else None
        return {
            "total": visible("total", summary["total"]),
            "initiated": visible("initiated", summary["initiated"]),
            "completed": visible("completed", completed),
            "terminated": visible("terminated", summary["terminated"]),
            "over_quota": visible("quota", summary["over_quota"]),
            "security_terminated": visible("security", summary["security_terminated"]),
            "conversion_rate": visible(
                "conversion",
                round((completed / summary["total"] * 100), 2) if summary["total"] else 0.0,
            ),
            "incidence_rate": visible(
                "ir", round((completed / ir_denominator * 100), 2) if ir_denominator else 0.0,
            ),
            "total_revenue": visible("revenue", summary["total_revenue"]),
            "revenue_currency": visible(
                "revenue", summary["revenue_currency"] or "USD"
            ),
            "completed_devices": {
                "desktop": visible("desktop", summary["desktop"]),
                "mobile": visible("mobile", summary["mobile"]),
                "tablet": visible("tablet", summary["tablet"]),
                "unclassified": max(0, completed - classified),
            },
        }

    @extend_schema(tags=["Survey attempts"], summary="List visible survey attempts with filter-aware totals", responses={200: SurveyAttemptListResponseSerializer})
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        summary = self._filtered_summary(queryset)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            response = self.get_paginated_response(serializer.data)
            response.data["summary"] = summary
            return response
        return Response({"count": queryset.count(), "next": None, "previous": None, "results": self.get_serializer(queryset, many=True).data, "summary": summary})

    def get_required_function_permission(self):
        return "attempts.export" if self.action == "export" else "attempts.view"

    def get_queryset(self):
        queryset = SurveyAttempt.objects.select_related(
            "survey", "survey__client", "survey__integration", "platform_user", "platform_user__employee_profile", "platform_user__employee_profile__role",
            "platform_user__employee_profile__organization_unit", "platform_user__employee_profile__organization_unit__parent",
            "platform_user__employee_profile__organization_unit__parent__parent",
            "vendor", "vendor__employee_profile", "client", "client_allocation", "survey_allocation",
        ).all()
        if self.request.user.is_superuser:
            return queryset
        visible_user_ids = activity_visible_user_ids(self.request.user)
        return queryset.filter(platform_user_id__in=visible_user_ids)

    def filter_queryset(self, queryset):
        _enforce_query_permissions(self.request, {
            "studies.filter.search": ("search",),
            "studies.filter.branch": ("branch",),
            "studies.filter.sub_branch": ("sub_branch",),
            "studies.filter.shift": ("shift",),
            "studies.filter.user": ("user",),
            "studies.filter.status": ("status",),
            "studies.filter.country": ("country",),
            "studies.filter.client": ("client",),
            "studies.filter.buyer": ("buyer_id",),
            "studies.filter.project": ("internal_id",),
            "studies.filter.date": ("initiated_from", "initiated_to", "callback_from", "callback_to"),
        })
        return super().filter_queryset(queryset)

    @extend_schema(
        tags=["Survey attempts"],
        summary="Export all filtered survey attempt data",
        description=(
            "Downloads the agreed Traffic Reports Excel columns for every filtered attempt, including immutable "
            "hit-time CPI, supplier CPI, respondent device/network audit and lifecycle timestamps."
        ),
        parameters=[
            OpenApiParameter("search", OpenApiTypes.STR, description="Search RID, user, survey, IP or client metadata."),
            OpenApiParameter("user", OpenApiTypes.STR, description="Comma-separated platform user IDs."),
            OpenApiParameter("branch", OpenApiTypes.STR, description="Comma-separated organization Branch IDs or legacy labels."),
            OpenApiParameter("sub_branch", OpenApiTypes.STR, description="Comma-separated organization Sub-branch IDs or legacy labels."),
            OpenApiParameter("shift", OpenApiTypes.STR, description="Comma-separated organization Shift IDs or legacy labels."),
            OpenApiParameter("status", OpenApiTypes.STR, description="Comma-separated attempt status codes."),
            OpenApiParameter("country", OpenApiTypes.STR, description="Comma-separated survey country codes."),
            OpenApiParameter("company", OpenApiTypes.STR, description="Comma-separated survey company names."),
            OpenApiParameter("client", OpenApiTypes.STR, description="Comma-separated internal client IDs."),
            OpenApiParameter("buyer_id", OpenApiTypes.STR, description="Comma-separated buyer/sub-client IDs."),
            OpenApiParameter("survey_id", OpenApiTypes.INT, description="Exact upstream survey ID."),
            OpenApiParameter("internal_id", OpenApiTypes.STR, description="Exact internal 14-digit project ID."),
            OpenApiParameter("entry_ip", OpenApiTypes.STR, description="Exact entry IP address."),
            OpenApiParameter("exit_ip", OpenApiTypes.STR, description="Exact exit IP address."),
            OpenApiParameter("initiated_from", OpenApiTypes.DATETIME, description="Entry timestamp lower bound (ISO 8601)."),
            OpenApiParameter("initiated_to", OpenApiTypes.DATETIME, description="Entry timestamp upper bound (ISO 8601)."),
            OpenApiParameter("callback_from", OpenApiTypes.DATETIME, description="Exit timestamp lower bound (ISO 8601)."),
            OpenApiParameter("callback_to", OpenApiTypes.DATETIME, description="Exit timestamp upper bound (ISO 8601)."),
            OpenApiParameter("ordering", OpenApiTypes.STR, description="Sort by initiated_at, callback_at, loi_seconds or status; prefix - for descending."),
        ],
        responses={(200, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"): OpenApiTypes.BINARY},
    )
    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        local_now = timezone.localtime()
        headers, rows, widths = _attempt_excel_rows(queryset, request.user)
        if not headers:
            raise PermissionDenied("No Traffic Report columns are assigned to your account.")
        return build_excel_response(
            f"traffic-reports-{local_now:%Y%m%d-%H%M%S}-IST.xlsx",
            [ExcelSheet("Traffic Reports", headers, rows, widths)],
        )


class DashboardFunctionPermission(HasFunctionPermission):
    """Resolve dashboard permissions once for the permission gate and payload."""

    def has_permission(self, request, view):
        user = request.user
        codes = effective_permission_codes(user)
        request._dashboard_permission_codes = codes
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and (user.is_superuser or "dashboard.view" in codes)
        )


class DashboardAPIView(APIView):
    permission_classes = [DashboardFunctionPermission]
    required_function_permission = "dashboard.view"

    @extend_schema(
        tags=["Dashboard"],
        summary="Get permission-scoped dashboard analytics",
        description=(
            "Returns permission-scoped KPI totals, incidence rate, immutable hit-time CPI revenue, "
            "client completion share, performance, outcome/device breakdowns and top users."
        ),
        parameters=[
            OpenApiParameter(
                "range", OpenApiTypes.STR,
                description="Global analytics window: 24h, 48h, 72h, 3m, 6m or 1y. Defaults to 24h.",
                enum=["24h", "48h", "72h", "3m", "6m", "1y"],
            ),
            OpenApiParameter(
                "traffic_range", OpenApiTypes.STR,
                description="Independent Traffic graph window; does not change dashboard cards.",
                enum=["24h", "48h", "72h", "3m", "6m", "1y"],
            ),
            OpenApiParameter(
                "traffic_client", OpenApiTypes.INT,
                description="Visible internal client ID for the Traffic graph only.",
            ),
            OpenApiParameter(
                "finance_range", OpenApiTypes.STR,
                description="Independent Revenue/RPC graph window; does not change dashboard cards.",
                enum=["24h", "48h", "72h", "3m", "6m", "1y"],
            ),
            OpenApiParameter(
                "finance_client", OpenApiTypes.INT,
                description="Visible internal client ID for the Revenue/RPC graph only.",
            ),
        ],
        responses={200: DashboardResponseSerializer},
    )
    def get(self, request):
        codes = getattr(request, "_dashboard_permission_codes", None)
        if codes is None:
            codes = effective_permission_codes(request.user)
        if any(request.query_params.get(key) not in {None, ""} for key in (
            "traffic_range", "traffic_client"
        )) and DASHBOARD_GRAPH_FILTER_PERMISSIONS["traffic"] not in codes:
            raise PermissionDenied("Your account cannot filter the Traffic dashboard graph.")
        if any(request.query_params.get(key) not in {None, ""} for key in (
            "finance_range", "finance_client"
        )) and DASHBOARD_GRAPH_FILTER_PERMISSIONS["finance"] not in codes:
            raise PermissionDenied("Your account cannot filter the Finance dashboard graph.")
        try:
            range_now = timezone.now()
            range_window = dashboard_range_window(
                request.query_params.get("range", "24h"), now=range_now
            )
            traffic_range_key = request.query_params.get("traffic_range") or range_window["key"]
            finance_range_key = request.query_params.get("finance_range") or range_window["key"]
            traffic_window = (
                range_window
                if traffic_range_key == range_window["key"]
                else dashboard_range_window(traffic_range_key, now=range_now)
            )
            finance_window = (
                range_window
                if finance_range_key == range_window["key"]
                else dashboard_range_window(finance_range_key, now=range_now)
            )
            visible_queryset = dashboard_attempts(request.user, {})
            client_options = dashboard_client_options(visible_queryset)
            visible_client_ids = {item["id"] for item in client_options}

            def selected_client(parameter):
                raw_value = str(request.query_params.get(parameter) or "").strip()
                if not raw_value:
                    return None
                try:
                    client_id = int(raw_value)
                except ValueError as exc:
                    raise ValueError("Graph client must be a numeric client ID.") from exc
                if client_id not in visible_client_ids:
                    raise ValueError("The selected graph client is not visible to this account.")
                return client_id

            traffic_client_id = selected_client("traffic_client")
            finance_client_id = selected_client("finance_client")

            graph_querysets = {}

            def graph_queryset(window, client_id=None):
                cache_key = (window["start"], window["end"], client_id)
                if cache_key not in graph_querysets:
                    scoped = visible_queryset.filter(
                        initiated_at__gte=window["start"], initiated_at__lte=window["end"]
                    )
                    graph_querysets[cache_key] = (
                        scoped.filter(survey__client_id=client_id) if client_id else scoped
                    )
                return graph_querysets[cache_key]

            queryset = graph_queryset(range_window)
            traffic_queryset = graph_queryset(traffic_window, traffic_client_id)
            finance_queryset = graph_queryset(finance_window, finance_client_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(build_dashboard_payload(
            queryset,
            request.user,
            _component_access(codes, DASHBOARD_CARD_PERMISSIONS),
            _component_access(codes, DASHBOARD_CHART_PERMISSIONS),
            range_window,
            traffic_queryset=traffic_queryset,
            traffic_range_window=traffic_window,
            traffic_client_id=traffic_client_id,
            finance_queryset=finance_queryset,
            finance_range_window=finance_window,
            finance_client_id=finance_client_id,
            client_options=client_options,
        ))


class UserHitsAPIView(APIView):
    permission_classes = [HasFunctionPermission]
    required_function_permission = "user_hits.view"

    @extend_schema(
        tags=["User hits"],
        summary="Aggregate user survey hits and completes by IST date and device",
        description=(
            "Returns one row per visible user and IST calendar date. Hits count initiated survey attempts; "
            "completes count status 1 within those attempts. Device splits use entry-device audit data."
        ),
        parameters=[
            OpenApiParameter("search", OpenApiTypes.STR, description="Search user, email, branch, sub-branch or shift."),
            OpenApiParameter("user", OpenApiTypes.STR, description="Comma-separated platform user IDs."),
            OpenApiParameter("branch", OpenApiTypes.STR, description="Comma-separated branch/company labels."),
            OpenApiParameter("sub_branch", OpenApiTypes.STR, description="Comma-separated sub-branch/department labels."),
            OpenApiParameter("shift", OpenApiTypes.STR, description="Comma-separated organization shift labels."),
            OpenApiParameter("from_date", OpenApiTypes.DATE, description="Inclusive IST entry date."),
            OpenApiParameter("to_date", OpenApiTypes.DATE, description="Inclusive IST entry date."),
            OpenApiParameter("from_time", OpenApiTypes.TIME, description="Optional inclusive IST start time; requires from_date."),
            OpenApiParameter("to_time", OpenApiTypes.TIME, description="Optional inclusive IST end time; requires to_date."),
            OpenApiParameter("page", OpenApiTypes.INT, description="1-based aggregate result page."),
            OpenApiParameter("page_size", OpenApiTypes.INT, description="Rows per page, 1–100."),
        ],
        responses={200: UserHitsResponseSerializer},
    )
    def get(self, request):
        _enforce_query_permissions(request, {
            "user_hits.filter.search": ("search",),
            "user_hits.filter.user": ("user",),
            "user_hits.filter.branch": ("branch",),
            "user_hits.filter.sub_branch": ("sub_branch",),
            "user_hits.filter.shift": ("shift",),
            "user_hits.filter.date": ("from_date", "from_time", "to_date", "to_time"),
        })
        try:
            rows, summary = aggregate_user_hits(request.user, request.query_params)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        codes = effective_permission_codes(request.user)
        if USER_HIT_CARD_PERMISSIONS["total_hits"] not in codes:
            summary["hits"]["total"] = None
        if USER_HIT_CARD_PERMISSIONS["completes"] not in codes:
            summary["completes"]["total"] = None
        if USER_HIT_CARD_PERMISSIONS["conversion"] not in codes:
            summary["conversion_rate"] = None
        if USER_HIT_CARD_PERMISSIONS["active_users"] not in codes:
            summary["active_users"] = None
        if USER_HIT_CARD_PERMISSIONS["devices"] not in codes:
            for device in ("desktop", "mobile", "tablet", "unclassified"):
                summary["completes"][device] = None
        if USER_HIT_CARD_PERMISSIONS["ir"] not in codes:
            summary["incidence_rate"] = None
        paginator = SurveyPagination()
        page = paginator.paginate_queryset(rows, request, view=self)
        response = paginator.get_paginated_response(page)
        response.data["summary"] = summary
        return response


class _CsvEcho:
    def write(self, value):
        return value


def _csv_safe(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif hasattr(value, "isoformat"):
        value = timezone.localtime(value).isoformat() if timezone.is_aware(value) else value.isoformat()
    else:
        value = str(value)
    return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value


def _excel_datetime(value):
    if not value:
        return ""
    local_value = timezone.localtime(value) if timezone.is_aware(value) else value
    return local_value.strftime("%d %b %Y %I:%M:%S %p IST")


def _survey_excel_rows(queryset, request, columns):
    can_view_client_name = has_function_access(request.user, "projects.column.client_name")
    survey_headers = ["Survey ID", "Survey name"]
    survey_widths = [16, 32]
    if can_view_client_name:
        survey_headers.append("Client")
        survey_widths.append(21)
    survey_headers.append("Buyer ID")
    survey_widths.append(15)
    headers_by_column = {
        "project_id": ["Project ID"],
        "survey": survey_headers,
        "market": ["Country code", "Country", "Language code", "Language"],
        "completes": ["Sample size", "Completes", "Remaining", "Progress (%)"],
        "cpi": ["CPI"],
        "loi_ir": ["LOI (minutes)", "Incidence rate (%)", "Survey type"],
        "entry_link": ["Entry link"],
        "modified": ["Status", "Source created at", "Source modified at", "Record created at", "Record updated at"],
    }
    widths_by_column = {
        "project_id": [19], "survey": survey_widths, "market": [13, 20, 14, 18],
        "completes": [13, 12, 12, 14], "cpi": [11], "loi_ir": [15, 18, 14],
        "entry_link": [48], "modified": [14, 22, 22, 22, 22],
    }
    export_columns = [column for column in columns if column in headers_by_column]
    headers = [header for column in export_columns for header in headers_by_column[column]]
    widths = [width for column in export_columns for width in widths_by_column[column]]

    def rows():
        serializer_context = {"request": request}
        for survey in queryset.iterator(chunk_size=500):
            data = SurveyListSerializer(survey, context=serializer_context).data
            values_by_column = {
                "project_id": [data.get("local_id")],
                "survey": (
                    [data.get("source_id"), data.get("name")]
                    + ([data.get("client_name") or data.get("display_company_name") or data.get("company_name")] if can_view_client_name else [])
                    + [data.get("buyer_id")]
                ),
                "market": [data.get("country_code"), data.get("country"), data.get("language_code"), data.get("language")],
                "completes": [data.get("sample_size"), data.get("completes"), data.get("remaining"), data.get("progress_percent")],
                "cpi": [data.get("cpi")],
                "loi_ir": [data.get("loi"), data.get("incidence_rate"), data.get("survey_type") or data.get("group_type")],
                "entry_link": [data.get("start_link")],
                "modified": [
                    data.get("status"), data.get("source_created_at"), data.get("source_modified_at"),
                    data.get("created_at"), data.get("updated_at"),
                ],
            }
            yield [value for column in export_columns for value in values_by_column[column]]

    return headers, rows(), widths


def _attempt_excel_rows(queryset, requesting_user=None):
    """Build Traffic Report rows without leaking upstream commercial data.

    Platform admins receive the source CPI, computed supplier CPI and supplier
    identity. Scoped/cut users receive only their adjusted CPI in the two client
    CPI columns; supplier commercial columns do not exist in their workbook.
    """

    commercial_admin = can_view_report_commercials(requesting_user)
    permitted = set(_permitted_columns(
        effective_permission_codes(requesting_user), STUDY_COLUMN_PERMISSIONS
    ))
    specs = {
        "project_id": (["Project id", "Client name"], [19, 21]),
        "survey_id": (["Cleint survey id"], [18]),
        "pid": (["PID"], [12]),
        "respondent_id": (["RID"], [14]),
        "status": (["Status", "Status source"], [19, 18]),
        "country": (["Country"], [18]),
        "cpi": (
            ["Current Client CPI", "Client entry link CPI"]
            + (["Vendor CPI", "Vendor name"] if commercial_admin else []),
            [18, 20] + ([14, 20] if commercial_admin else []),
        ),
        "user": (["User name"], [22]),
        "device": (["Device", "OS", "Browser", "User agent"], [13, 16, 18, 42]),
        "ip": (["Entry IP", "Exit IP"], [16, 16]),
        "loi": (["Actual LOI (minutes)"], [19]),
        "start": (
            ["Inisitate at", "Presecreent at", "Redirect at", "entry date time"],
            [22, 22, 22, 22],
        ),
        "end": (["Exit date time"], [22]),
    }
    ordered_columns = [column for column in STUDY_COLUMN_PERMISSIONS if column in permitted]
    headers = [header for column in ordered_columns for header in specs[column][0]]
    widths = [width for column in ordered_columns for width in specs[column][1]]

    def rows():
        for attempt in queryset.iterator(chunk_size=1000):
            survey = attempt.survey
            user = attempt.platform_user
            client = attempt.client or survey.client
            status_label = (
                "Initiated"
                if attempt.status in {SurveyAttempt.Status.INITIATED, SurveyAttempt.Status.REDIRECTED}
                else attempt.get_status_display()
            )
            values_by_column = {
                "project_id": [survey.local_id, client.name if client else survey.company_name],
                "survey_id": [survey.source_identifier],
                "pid": [attempt.pid],
                "respondent_id": [attempt.rid],
                "status": [status_label, attempt.status_source],
                "country": [survey.country or survey.country_code],
                "cpi": [
                    viewer_attempt_cpi(attempt, requesting_user, current=True),
                    viewer_attempt_cpi(attempt, requesting_user),
                    *(
                        [supplier_cpi_for_admin(attempt), supplier_label_for_admin(attempt)]
                        if commercial_admin else []
                    ),
                ],
                "user": [(user.get_full_name() or user.username) if user else "Deleted user"],
                "device": [
                    attempt.entry_device, attempt.entry_os, attempt.entry_browser,
                    attempt.entry_user_agent,
                ],
                "ip": [attempt.initiation_ip, attempt.callback_ip],
                "loi": [round((attempt.loi_seconds or 0) / 60, 2)],
                "start": [
                    _excel_datetime(attempt.initiated_at), _excel_datetime(attempt.submitted_at),
                    _excel_datetime(attempt.redirected_at), _excel_datetime(attempt.created_at),
                ],
                "end": [_excel_datetime(attempt.callback_at or attempt.last_callback_at)],
            }
            yield [value for column in ordered_columns for value in values_by_column[column]]

    return headers, rows(), widths


def _survey_csv_rows(queryset, request, columns):
    headers_by_column = {
        "project_id": ["Project ID"],
        "survey": ["Survey ID", "Survey name", "Client", "Buyer ID"],
        "market": ["Country code", "Country", "Language code", "Language"],
        "completes": ["Sample size", "Completes", "Remaining", "Progress (%)"],
        "cpi": ["CPI"],
        "loi_ir": ["LOI (minutes)", "Incidence rate (%)", "Survey type"],
        "entry_link": ["Entry link"],
        "modified": ["Status", "Source created at", "Source modified at", "Record created at", "Record updated at"],
    }
    export_columns = [column for column in columns if column in headers_by_column]
    headers = [header for column in export_columns for header in headers_by_column[column]]
    writer = csv.writer(_CsvEcho())
    yield "\ufeff" + writer.writerow(headers)
    serializer_context = {"request": request}
    for survey in queryset.iterator(chunk_size=500):
        data = SurveyListSerializer(survey, context=serializer_context).data
        values_by_column = {
            "project_id": [data.get("local_id")],
            "survey": [
                data.get("source_id"), data.get("name"),
                data.get("client_name") or data.get("display_company_name") or data.get("company_name"),
                data.get("buyer_id"),
            ],
            "market": [data.get("country_code"), data.get("country"), data.get("language_code"), data.get("language")],
            "completes": [data.get("sample_size"), data.get("completes"), data.get("remaining"), data.get("progress_percent")],
            "cpi": [data.get("cpi")],
            "loi_ir": [data.get("loi"), data.get("incidence_rate"), data.get("survey_type") or data.get("group_type")],
            "entry_link": [data.get("start_link")],
            "modified": [
                data.get("status"), data.get("source_created_at"), data.get("source_modified_at"),
                data.get("created_at"), data.get("updated_at"),
            ],
        }
        values = [value for column in export_columns for value in values_by_column[column]]
        yield writer.writerow([_csv_safe(value) for value in values])


def _attempt_csv_rows(queryset, requesting_user=None):
    headers = [
        "Respondent ID (RID)", "Status code", "Status", "Termination reason", "Termination category", "Status source", "Platform user ID", "Username", "Employee name",
        "Email", "Employee ID", "Account type", "Role", "Supplier ID", "Supplier name", "Supplier account type",
        "Client ID", "Client name", "Client allocation ID", "Survey allocation ID",
        "Internal project ID", "Survey ID", "Survey name", "Company", "Buyer ID", "Survey type", "Country", "Language", "Supplier code",
        "Current survey CPI", "Source CPI snapshot", "CPI snapshot source", "CPI cut snapshot (%)", "Payable CPI snapshot",
        "CPI currency snapshot", "Expected LOI (minutes)",
        "Actual LOI (seconds)", "Entry IP", "Exit IP", "Entry browser", "Exit browser", "Entry device",
        "Exit device", "Entry OS", "Exit OS", "Entry user agent", "Exit user agent", "Entry referrer",
        "Entry accept language", "Initiated at (IST)", "Pre-screener submitted at (IST)",
        "Redirected at (IST)", "First callback at (IST)", "Last callback at (IST)", "Callback count",
        "Verified", "Last upstream check (IST)", "Upstream transaction", "Pre-screener answers",
        "Outbound supplier URL", "Entry client metadata", "Exit client metadata", "Record created at (IST)",
        "Record updated at (IST)",
    ]
    writer = csv.writer(_CsvEcho())
    yield "\ufeff" + writer.writerow(headers)
    hide_source_cpi = is_external_vendor_scope(requesting_user)
    def visible_cpi(value):
        if hide_source_cpi or value is None:
            return ""
        return visible_cpi_for_user(requesting_user, value)

    for attempt in queryset.iterator(chunk_size=1000):
        outcome = provider_outcome(attempt) if attempt.status in {
            SurveyAttempt.Status.TERMINATED,
            SurveyAttempt.Status.OVER_QUOTA,
            SurveyAttempt.Status.QUALITY_TERMINATED,
        } else {"reason": "", "category": ""}
        user = attempt.platform_user
        profile = getattr(user, "employee_profile", None) if user else None
        role = getattr(profile, "role", None) if profile else None
        vendor = attempt.vendor
        vendor_profile = getattr(vendor, "employee_profile", None) if vendor else None
        survey = attempt.survey
        values = [
            attempt.rid, attempt.status,
            "Initiated" if attempt.status in {SurveyAttempt.Status.INITIATED, SurveyAttempt.Status.REDIRECTED} else attempt.get_status_display(),
            outcome["reason"], outcome["category"], attempt.status_source, user.pk if user else attempt.user_id,
            user.username if user else "", (user.get_full_name() or user.username) if user else "Deleted user",
            user.email if user else "", getattr(profile, "employee_id", ""),
            profile.get_account_type_display() if profile else "", role.name if role else "",
            vendor.pk if vendor else "", (vendor.get_full_name() or vendor.username) if vendor else "",
            vendor_profile.get_account_type_display() if vendor_profile else "",
            attempt.client_id, attempt.client.name if attempt.client else "", attempt.client_allocation_id,
            attempt.survey_allocation_id,
            survey.local_id, survey.source_identifier, survey.name, survey.company_name, survey.buyer_id, survey.survey_type or survey.group_type, survey.country_code,
            survey.language_code, attempt.supplier_code,
            visible_cpi(survey.cpi),
            visible_cpi(attempt.source_cpi_snapshot),
            attempt.cpi_snapshot_source, attempt.cpi_cut_percent_snapshot,
            visible_cpi_for_user(requesting_user, attempt.payable_cpi_snapshot), attempt.cpi_currency_snapshot,
            survey.loi, attempt.loi_seconds,
            attempt.initiation_ip, attempt.callback_ip, attempt.entry_browser, attempt.exit_browser,
            attempt.entry_device, attempt.exit_device, attempt.entry_os, attempt.exit_os,
            attempt.entry_user_agent, attempt.exit_user_agent, attempt.entry_referrer,
            attempt.entry_accept_language, attempt.initiated_at, attempt.submitted_at, attempt.redirected_at,
            attempt.callback_at, attempt.last_callback_at, attempt.callback_count, attempt.is_verified,
            attempt.upstream_checked_at, attempt.upstream_transaction_data, attempt.answers, attempt.outbound_url,
            attempt.entry_client_data, attempt.exit_client_data,
            attempt.created_at, attempt.updated_at,
        ]
        yield writer.writerow([_csv_safe(value) for value in values])
