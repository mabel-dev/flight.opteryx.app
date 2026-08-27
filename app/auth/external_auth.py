"""External authentication service client.

This module handles communication with the external authentication service
(authenticate.opteryx.app) to convert basic auth credentials into JWTs.

Ported from odata.opteryx's `app/auth/external_auth.py`; the only change is
that FastAPI's `HTTPException` is replaced with the transport-agnostic
`AuthError` (see `app.auth.errors`), since Flight has no HTTP status codes.
"""

import os
from typing import Any
from typing import Dict

import requests
from jose import JWTError
from jose import jwt as jose_jwt
from opteryx_shared_services.logging import get_logger

from app.auth.errors import AuthError
from opteryx_shared_services.config import get_config

logger = get_logger()


def authenticate_with_external_service(username: str, password: str) -> Dict[str, Any]:
    """Authenticate credentials with external auth service and return JWT claims.

    This function calls the external authentication service at authenticate.opteryx.app
    using the OAuth2 client_credentials grant type. The service validates the credentials
    and returns a JWT access token containing user identity and permissions.

    Args:
        username: The username (used as client_id)
        password: The password (used as client_secret)

    Returns:
        dict: JWT claims including:
            - identity (str): User identifier from sub/email/preferred_username
            - permissions (list[tuple[str, str]]): List of (role, workspace) tuples
            - Other standard JWT claims (exp, iss, aud, etc.)

    Raises:
        AuthError(401): Invalid credentials
        AuthError(503): Auth service unavailable or timeout
    """
    auth_url = get_config("AUTH_URL", "https://authenticate.opteryx.app")
    token_endpoint = f"{auth_url.rstrip('/')}/token"
    timeout = float(os.environ.get("AUTH_SERVICE_TIMEOUT", "10"))

    # Prepare request data for OAuth2 client_credentials grant
    data = {
        "grant_type": "client_credentials",
        "client_id": username,
        "client_secret": password,
    }

    try:
        response = requests.post(
            token_endpoint,
            params={"set_cookie": "false"},  # Add query parameter
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )

        # Handle authentication failures
        if response.status_code == 401:
            logger.info(f"Authentication failed for user '{username}': invalid credentials")
            raise AuthError(401, "Invalid username or password")

        if response.status_code == 403:
            logger.info(f"Authentication forbidden for user '{username}'")
            raise AuthError(401, "Access forbidden")

        # Handle service errors
        if response.status_code >= 500:
            logger.error(
                f"Auth service returned server error: {response.status_code} - {response.text}"
            )
            raise AuthError(503, "Authentication service unavailable")

        # Handle other non-200 responses
        if response.status_code != 200:
            logger.warning(
                f"Auth service returned unexpected status {response.status_code}: {response.text}"
            )
            raise AuthError(503, "Authentication service error")

        # Parse response and extract access token
        response_data = response.json()
        access_token = response_data.get("access_token")

        if not access_token:
            logger.error(f"Auth service response missing access_token: {response_data}")
            raise AuthError(503, "Invalid auth service response")

        # Decode JWT to extract claims (no verification needed - already validated by auth service)
        try:
            claims = jose_jwt.get_unverified_claims(access_token)
        except JWTError as exc:
            logger.error(f"Failed to decode JWT from auth service: {exc}")
            raise AuthError(503, "Invalid token from auth service") from exc

        # Extract identity from standard JWT claims
        identity = (
            claims.get("sub") or claims.get("email") or claims.get("preferred_username") or username
        )

        # Policies claim encodes what a user can access. Keep policies untouched
        # (do not convert into a separate "permissions" claim which is incorrect).
        policies = claims.get("policies", [])

        # Add identity to claims for easy access
        claims["identity"] = identity

        # This path does not go through _normalize_claims, so derive the billing
        # account here too — otherwise basic-auth callers bill to the house account.
        from app.auth.permissions import billing_account_from_claims

        claims["billing_account"] = billing_account_from_claims(claims)

        logger.info(
            f"Successfully authenticated user '{username}' (identity: {identity}) with {len(policies)} policies"
        )

        return claims

    except requests.Timeout as exc:
        logger.error(f"Auth service timeout after {timeout}s for user '{username}'")
        raise AuthError(503, f"Authentication service timeout after {timeout}s") from exc

    except requests.RequestException as exc:
        logger.error(f"Auth service connection error for user '{username}': {exc}")
        raise AuthError(503, "Authentication service unavailable") from exc
