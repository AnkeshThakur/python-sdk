import time
from enum import Enum
from typing import Any

from starlette.requests import Request

from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.shared.auth import OAuthClientInformationFull


class ClientAuthMethod(Enum):
    """OAuth 2.1 client authentication methods."""
    FORM = "form"  # client_id and client_secret in form data
    BASIC = "basic"  # HTTP Basic authentication
    NONE = "none"  # Public client, no authentication


class AuthenticationError(Exception):
    def __init__(self, message: str, auth_method: ClientAuthMethod | None = None):
        self.message = message
        self.auth_method = auth_method


class ClientAuthenticator:
    """
    ClientAuthenticator is a callable which validates requests from a client
    application, used to verify /token calls.
    If, during registration, the client requested to be issued a secret, the
    authenticator asserts that /token calls must be authenticated with
    that same token.
    NOTE: clients can opt for no authentication during registration, in which case this
    logic is skipped.
    """

    def __init__(self, provider: OAuthAuthorizationServerProvider[Any, Any, Any]):
        """
        Initialize the dependency.

        Args:
            provider: Provider to look up client information
        """
        self.provider = provider

    def _detect_auth_method(self, request: Request, client_secret: str | None) -> ClientAuthMethod:
        """Detect the authentication method used by the client."""
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("basic "):
            return ClientAuthMethod.BASIC
        elif client_secret is not None:
            return ClientAuthMethod.FORM
        else:
            return ClientAuthMethod.NONE

    async def authenticate(
        self, request: Request, client_id: str, client_secret: str | None
    ) -> OAuthClientInformationFull:
        # Detect authentication method for proper error responses
        auth_method = self._detect_auth_method(request, client_secret)

        # Look up client information
        client = await self.provider.get_client(client_id)
        if not client:
            raise AuthenticationError("Invalid client_id", auth_method)

        # If client from the store expects a secret, validate that the request provides
        # that secret
        if client.client_secret:
            if not client_secret:
                raise AuthenticationError("Client secret is required", auth_method)

            if client.client_secret != client_secret:
                raise AuthenticationError("Invalid client_secret", auth_method)

            if client.client_secret_expires_at and client.client_secret_expires_at < int(time.time()):
                raise AuthenticationError("Client secret has expired", auth_method)

        return client
