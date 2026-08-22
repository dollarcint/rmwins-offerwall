"""Dedicated InnovateMR HTTP client used by legacy sync and reconciliation."""

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class InnovateMRAPIError(RuntimeError):
    """Raised when a configured survey provider returns an invalid response."""


class InnovateMRNotFound(InnovateMRAPIError):
    """Raised when a survey-provider resource does not exist."""


@dataclass
class PagedSurveyResult:
    surveys: list[dict[str, Any]]
    pages: int


BIOBRAIN_FIELD_MAP = {
    "surveyId": "SurveyId", "surveyName": "Name", "CPI": "Revenue", "IR": "IncidentRate",
    "LOI": "LengthOfInterview", "N": "Completes", "supCmps": "Completes",
    "remainingN": "Completes", "entryLink": "SurveyUrl",
    "isQuota": "Has_Quotas", "isPIIRequired": "CollectPii", "createdDate": "StartDate",
    "modifiedDate": "LastUpdatedOnUTC", "Language": "LanguageId",
}


def _path_value(payload: Any, path: str, default=None):
    value = payload
    for part in str(path or "").split("."):
        if not part:
            continue
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


class InnovateMRClient:
    """Configurable survey-provider client; class name is retained for API compatibility."""

    def __init__(self, token: str | None = None, session: requests.Session | None = None, integration=None):
        self.integration = integration
        if integration is not None:
            if token is None:
                from vendors.credentials import resolve_integration_token
                token = resolve_integration_token(integration)
            # Never borrow the global InnovateMR key for another client.
            self.token = token or ""
        else:
            self.token = token if token is not None else settings.INNOVATEMR_API_TOKEN
        self.base_url = (integration.base_url if integration is not None else settings.INNOVATEMR_BASE_URL).rstrip("/")
        self.provider_code = (getattr(integration, "provider_code", "innovatemr") or "innovatemr").lower()
        self.provider_key = self.provider_code.replace("-", "").replace("_", "")
        self.is_biobrain = self.provider_key in {"biobrain", "voqall"} or "voqall.com" in self.base_url.lower()
        self.timeout = settings.INNOVATEMR_TIMEOUT_SECONDS
        self.page_size = settings.INNOVATEMR_PAGE_SIZE
        self.max_pages = settings.INNOVATEMR_MAX_PAGES
        self._session = session
        self._owns_session = session is None
        self._session_closed = False

    @property
    def session(self) -> requests.Session:
        """Create the owned connection pool only when a request is made."""

        if self._owns_session and self._session_closed:
            raise InnovateMRAPIError("This upstream client is already closed.")
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def close(self) -> None:
        """Release an internally-created pool without closing caller-owned sessions."""

        if not self._owns_session or self._session_closed:
            return
        self._session_closed = True
        if self._session is None:
            return
        try:
            self._session.close()
        except Exception:
            logger.warning("Could not close an InnovateMR HTTP session", exc_info=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _config(self, name: str, default=""):
        return getattr(self.integration, name, default) if self.integration is not None else default

    def _endpoint(self, name: str, innovate_default: str = "", biobrain_default: str = "") -> str:
        configured = self._config(name, "")
        if configured:
            return configured
        if self.is_biobrain:
            return biobrain_default
        if self.provider_key == "innovatemr":
            return innovate_default
        return ""

    def _url(self, endpoint: str) -> str:
        endpoint = str(endpoint or "").strip()
        if not endpoint:
            return self.base_url
        if urlparse(endpoint).scheme in {"http", "https"}:
            return endpoint
        return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

    def _headers(self) -> dict[str, str]:
        if not self.token:
            raise InnovateMRAPIError(f"API token is not configured for {self.provider_code}")
        default_header = "EQ-PARTNER-ACCESS-KEY" if self.is_biobrain else "x-access-token"
        header_name = str(self._config("auth_header_name", "") or default_header).strip()
        prefix = str(self._config("auth_header_prefix", "") or "").strip()
        return {header_name: f"{prefix} {self.token}" if prefix else self.token, "Accept": "application/json"}

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        url = self._url(endpoint)
        try:
            response = self.session.get(url, params=params, headers=self._headers(), timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                raise InnovateMRNotFound(f"{self.provider_code} returned no data for {url}") from exc
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        except (requests.RequestException, ValueError) as exc:
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        if not isinstance(payload, (dict, list)):
            raise InnovateMRAPIError(f"{self.provider_code} returned an invalid JSON payload")
        if isinstance(payload, dict) and self.provider_key == "innovatemr" and payload.get("apiStatus") not in {None, "success"}:
            raise InnovateMRAPIError(f"InnovateMR rejected the request: {payload.get('msg', 'Unexpected response')}")
        if isinstance(payload, dict) and self.is_biobrain and payload.get("hasError") is True:
            messages = payload.get("messages") or []
            raise InnovateMRAPIError(f"Bio Brain rejected the request: {'; '.join(str(item) for item in messages) or str(payload.get('error') or 'Unexpected response')}")
        return payload

    def _post(self, endpoint: str, body: dict[str, Any]) -> Any:
        url = self._url(endpoint)
        try:
            response = self.session.post(
                url, json=body, headers=self._headers(), timeout=self.timeout
            )
            response.raise_for_status()
            payload = response.json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                raise InnovateMRNotFound(f"{self.provider_code} returned no data for {url}") from exc
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        except (requests.RequestException, ValueError) as exc:
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        if not isinstance(payload, (dict, list)):
            raise InnovateMRAPIError(f"{self.provider_code} returned an invalid JSON payload")
        if isinstance(payload, dict) and self.provider_key == "innovatemr" and payload.get("apiStatus") not in {None, "success"}:
            raise InnovateMRAPIError(f"InnovateMR rejected the request: {payload.get('msg', 'Unexpected response')}")
        return payload

    def request_json(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        """Execute one server-configured read request for the admin API explorer.

        Authentication is still resolved internally. Callers receive only the
        provider JSON payload, never request headers or credential values.
        """
        return self._get(endpoint, params=params)

    def post_json(self, endpoint: str, body: dict[str, Any]) -> Any:
        """Execute one allow-listed, non-mutating provider check via POST."""
        return self._post(endpoint, body)

    def write_json(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        """Execute an explicitly confirmed provider configuration/profile mutation.

        This method is intentionally separate from the inventory helpers so a
        caller cannot turn an arbitrary Swagger request into an upstream write.
        The explorer allow-list and confirmation gate are enforced before this
        method is reached.
        """
        method = str(method or "").upper()
        if method not in {"POST", "PUT", "DELETE"}:
            raise InnovateMRAPIError("Unsupported upstream write method")
        url = self._url(endpoint)
        try:
            response = self.session.request(
                method,
                url,
                json=body or {},
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                raise InnovateMRNotFound(f"{self.provider_code} returned no data for {url}") from exc
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        except (requests.RequestException, ValueError) as exc:
            raise InnovateMRAPIError(f"{self.provider_code} request failed for {url}: {exc}") from exc
        if not isinstance(payload, (dict, list)):
            raise InnovateMRAPIError(f"{self.provider_code} returned an invalid JSON payload")
        if (
            isinstance(payload, dict)
            and self.provider_key == "innovatemr"
            and payload.get("apiStatus") not in {None, "success"}
        ):
            raise InnovateMRAPIError(
                f"InnovateMR rejected the request: {payload.get('msg', 'Unexpected response')}"
            )
        return payload

    def endpoint_url(self, endpoint: str) -> str:
        """Return the non-secret effective URL used for documentation metadata."""
        return self._url(endpoint)

    def _result_list(self, payload: Any, key: str) -> list[dict[str, Any]]:
        result = _path_value(payload, key, []) if isinstance(payload, dict) else payload
        if not isinstance(result, list):
            raise InnovateMRAPIError(f"{self.provider_code} response field '{key or '<root>'}' must be a list")
        return [item for item in result if isinstance(item, dict)]

    def _normalize_survey(self, item: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(item)
        mapping = dict(BIOBRAIN_FIELD_MAP if self.is_biobrain else {})
        custom_mapping = self._config("field_mapping", {}) or {}
        if isinstance(custom_mapping, dict):
            mapping.update({str(key): str(value) for key, value in custom_mapping.items() if value})
        for canonical, upstream in mapping.items():
            value = _path_value(item, upstream)
            if value is not None:
                normalized[canonical] = value
        if self.is_biobrain:
            normalized.setdefault("CPI", item.get("Cpi")); normalized.setdefault("IR", item.get("Ir")); normalized.setdefault("LOI", item.get("Loi"))
            normalized["deviceType"] = ", ".join(name for name, field in (("desktop", "DesktopAllowed"), ("mobile", "MobileAllowed"), ("tablet", "TabletAllowed")) if item.get(field))
        normalized["_provider_name"] = getattr(getattr(self.integration, "client", None), "name", self.provider_code)
        return normalized

    def _enrich_biobrain_market(self, surveys: list[dict[str, Any]]) -> None:
        """Resolve Bio Brain's LanguageId into displayable country/language fields."""
        language_ids = {
            str(item.get("LanguageId") or "").strip()
            for item in surveys
            if str(item.get("LanguageId") or "").strip()
        }
        if not language_ids:
            return
        api_root = self.base_url[:-8] if self.base_url.lower().endswith("/surveys") else self.base_url
        try:
            payload = self._get(f"{api_root}/collection/languages")
            rows = self._result_list(payload, "Languages")
        except InnovateMRAPIError:
            logger.warning("Could not resolve Bio Brain language/country collection", exc_info=True)
            return
        languages = {str(row.get("Id") or "").strip(): row for row in rows}
        for survey in surveys:
            language = languages.get(str(survey.get("LanguageId") or "").strip())
            if not language:
                continue
            display_name = str(language.get("Name") or "").strip()
            language_name, separator, country_name = display_name.partition(" - ")
            survey["CountryCode"] = str(language.get("CountryCode") or "").strip().upper()
            survey["Country"] = country_name.strip() if separator else display_name
            survey["Language"] = language_name.strip() if separator else display_name

    def get_allocated_surveys(self) -> list[dict[str, Any]]:
        endpoint = self._endpoint("inventory_endpoint", "/supply/getAllocatedSurveys", "")
        key = str(self._config("inventory_result_key", "") or ("Surveys" if self.is_biobrain else "result"))
        surveys = [self._normalize_survey(item) for item in self._result_list(self._get(endpoint), key)]
        if self.is_biobrain:
            self._enrich_biobrain_market(surveys)
        return surveys

    def test_connection(self) -> dict[str, Any]:
        surveys = self.get_allocated_surveys()
        return {"ok": True, "provider": self.provider_code, "endpoint": self._url(self._endpoint("inventory_endpoint", "/supply/getAllocatedSurveys", "")), "records_visible": len(surveys)}

    def get_allocated_surveys_paged(self) -> PagedSurveyResult:
        endpoint = self._endpoint("paged_inventory_endpoint", "/supply/getAllocatedSurveysPaged", "")
        if not endpoint:
            return PagedSurveyResult(surveys=[], pages=0)
        surveys=[]; next_cursor=None; seen_cursors=set(); key=str(self._config("inventory_result_key", "") or "result")
        for page_number in range(1, self.max_pages + 1):
            params={"limit": self.page_size}
            if next_cursor: params["next"] = next_cursor
            payload=self._get(endpoint, params=params); surveys.extend(self._normalize_survey(item) for item in self._result_list(payload, key))
            paging=payload.get("paging") or {} if isinstance(payload, dict) else {}; candidate=paging.get("next") if isinstance(paging, dict) else None
            if not candidate or candidate in seen_cursors: return PagedSurveyResult(surveys=surveys, pages=page_number)
            seen_cursors.add(candidate); next_cursor=candidate
        raise InnovateMRAPIError(f"Pagination exceeded max pages ({self.max_pages})")

    def get_quota_for_survey(self, survey_id: int) -> list[dict[str, Any]]:
        endpoint=self._endpoint("quota_endpoint_template", "/supply/getQuotaForSurvey/{survey_id}", "")
        if not endpoint: return []
        key=str(self._config("quota_result_key", "") or ("Quotas" if self.is_biobrain else "result")); items=self._result_list(self._get(endpoint.format(survey_id=survey_id)), key)
        return [{**item, "id": item.get("QuotaId"), "targeting": {"Conditions": item.get("Conditions", [])}} for item in items] if self.is_biobrain else items

    def _biobrain_qualification_detail(self, language_id: Any, qualification_id: Any) -> dict[str, Any]:
        if language_id in (None, "") or qualification_id in (None, ""):
            return {}
        api_root = self.base_url[:-8] if self.base_url.lower().endswith("/surveys") else self.base_url
        payload = self._get(
            f"{api_root}/collection/languages/{language_id}/qualifications/{qualification_id}"
        )
        rows = self._result_list(payload, "Qualification")
        return rows[0] if rows else {}

    def get_survey_targeting(self, survey_id: int, language_id: Any = None) -> list[dict[str, Any]]:
        endpoint=self._endpoint("targeting_endpoint_template", "/supply/getSurveyTargeting/{survey_id}", "")
        if not endpoint: return []
        key=str(self._config("targeting_result_key", "") or ("Qualifications" if self.is_biobrain else "result")); items=self._result_list(self._get(endpoint.format(survey_id=survey_id)), key)
        if not self.is_biobrain:
            return items
        normalized = []
        for item in items:
            qualification_id = item.get("QualificationId")
            try:
                detail = self._biobrain_qualification_detail(language_id, qualification_id)
            except InnovateMRAPIError:
                logger.warning(
                    "Could not resolve Bio Brain qualification detail survey=%s qualification=%s",
                    survey_id,
                    qualification_id,
                    exc_info=True,
                )
                detail = {}
            allowed_values = item.get("OptionCodes") or item.get("OptionIds") or []
            options = [
                {
                    "OptionId": option.get("OptionCode"),
                    "OptionText": option.get("OptionText") or str(option.get("OptionCode") or ""),
                }
                for option in (detail.get("Options") or [])
                if isinstance(option, dict)
            ]
            age_ranges = []
            if str(detail.get("Code") or "").upper() == "AGE":
                for value in allowed_values:
                    match = re.fullmatch(
                        r"(\d{1,3})\s*(?:-|\u2013|to)\s*(\d{1,3})",
                        str(value),
                        re.IGNORECASE,
                    )
                    if match:
                        age_ranges.append({"min": int(match.group(1)), "max": int(match.group(2))})
            normalized.append({
                **item,
                "QuestionId": qualification_id,
                "QuestionKey": str(detail.get("Code") or qualification_id or ""),
                "QuestionText": str(detail.get("QuestionText") or ""),
                "QuestionType": str(detail.get("TypeName") or item.get("QualificationTypeId") or ""),
                "QuestionCategory": "Profile",
                "Options": options,
                "targeting_choices": [str(value) for value in allowed_values],
                "targeting_age_ranges": age_ranges,
            })
        return normalized

    def get_survey_transactions_by_pid(self, survey_id: int, pid: str) -> list[dict[str, Any]]:
        endpoint=self._endpoint("transaction_endpoint_template", "/supply/getSurveyTransactionsByCond/{survey_id}/{pid}", "")
        if not endpoint: return []
        return self._result_list(self._get(endpoint.format(survey_id=survey_id, pid=pid)), str(self._config("transaction_result_key", "") or "result"))
