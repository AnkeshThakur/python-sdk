import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, RootModel, ValidationError
from starlette.requests import Request

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator, ClientAuthMethod
from mcp.server.auth.provider import OAuthAuthorizationServerProvider, TokenError, TokenErrorCode
from mcp.shared.auth import OAuthToken


class AuthorizationCodeRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    grant_type: Literal["authorization_code"]
    code: str = Field(..., description="The authorization code")
    redirect_uri: AnyUrl | None = Field(None, description="Must be the same as redirect URI provided in /authorize")
    client_id: str
    # we use the client_secret param, per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    client_secret: str | None = None
    # See https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
    code_verifier: str = Field(..., description="PKCE code verifier")
    # RFC 8707 resource indicator
    resource: str | None = Field(None, description="Resource indicator for the token")


class RefreshTokenRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-6
    grant_type: Literal["refresh_token"]
    refresh_token: str = Field(..., description="The refresh token")
    scope: str | None = Field(None, description="Optional scope parameter")
    client_id: str
    # we use the client_secret param, per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    client_secret: str | None = None
    # RFC 8707 resource indicator
    resource: str | None = Field(None, description="Resource indicator for the token")


class TokenRequest(
    RootModel[
        Annotated[
            AuthorizationCodeRequest | RefreshTokenRequest,
            Field(discriminator="grant_type"),
        ]
    ]
):
    root: Annotated[
        AuthorizationCodeRequest | RefreshTokenRequest,
        Field(discriminator="grant_type"),
    ]


class TokenErrorResponse(BaseModel):
    """
    See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """

    error: TokenErrorCode
    error_description: str | None = None
    error_uri: AnyHttpUrl | None = None


class TokenSuccessResponse(RootModel[OAuthToken]):
    # this is just a wrapper over OAuthToken; the only reason we do this
    # is to have some separation between the HTTP response type, and the
    # type returned by the provider
    root: OAuthToken


@dataclass
class TokenHandler:
    provider: OAuthAuthorizationServerProvider[Any, Any, Any]
    client_authenticator: ClientAuthenticator

    def response(
        self,
        obj: TokenSuccessResponse | TokenErrorResponse,
        auth_method: ClientAuthMethod | None = None
    ):
        status_code = 200
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }

        if isinstance(obj, TokenErrorResponse):
            # OAuth 2.1 compliant error handling
            if obj.error == "invalid_client":
                # For invalid_client, use HTTP 401 and add WWW-Authenticate header
                status_code = 401
                if auth_method == ClientAuthMethod.BASIC:
                    headers["WWW-Authenticate"] = 'Basic realm="OAuth Token Endpoint"'
                elif auth_method == ClientAuthMethod.FORM:
                    headers["WWW-Authenticate"] = 'Form'
                # For NONE (public clients), no WWW-Authenticate header needed
            else:
                # All other token errors use HTTP 400 per OAuth 2.1
                status_code = 400

        return PydanticJSONResponse(
            content=obj,
            status_code=status_code,
            headers=headers,
        )

    async def handle(self, request: Request):
        try:
            form_data = await request.form()
            token_request = TokenRequest.model_validate(dict(form_data)).root
        except ValidationError as validation_error:
            return self.response(
                TokenErrorResponse(
                    error="invalid_request",
                    error_description=stringify_pydantic_error(validation_error),
                )
            )

        try:
            client_info = await self.client_authenticator.authenticate(
                request=request,
                client_id=token_request.client_id,
                client_secret=token_request.client_secret,
            )
        except AuthenticationError as e:
            # OAuth 2.1 compliant: return invalid_client for authentication failures
            return self.response(
                TokenErrorResponse(
                    error="invalid_client",
                    error_description=e.message,
                ),
                auth_method=e.auth_method
            )

        if token_request.grant_type not in client_info.grant_types:
            return self.response(
                TokenErrorResponse(
                    error="unsupported_grant_type",
                    error_description=(f"Unsupported grant type (supported grant types are {client_info.grant_types})"),
                )
            )

        tokens: OAuthToken

        match token_request:
            case AuthorizationCodeRequest():
                auth_code = await self.provider.load_authorization_code(client_info, token_request.code)
                if auth_code is None or auth_code.client_id != token_request.client_id:
                    # if code belongs to different client, pretend it doesn't exist
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code does not exist",
                        )
                    )

                # make auth codes expire after a deadline
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.5
                if auth_code.expires_at < time.time():
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code has expired",
                        )
                    )

                # verify redirect_uri doesn't change between /authorize and /tokens
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                if auth_code.redirect_uri_provided_explicitly:
                    authorize_request_redirect_uri = auth_code.redirect_uri
                else:
                    authorize_request_redirect_uri = None

                # Convert both sides to strings for comparison to handle AnyUrl vs string issues
                token_redirect_str = str(token_request.redirect_uri) if token_request.redirect_uri is not None else None
                auth_redirect_str = (
                    str(authorize_request_redirect_uri) if authorize_request_redirect_uri is not None else None
                )

                if token_redirect_str != auth_redirect_str:
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_request",
                            error_description=("redirect_uri did not match the one used when creating auth code"),
                        )
                    )

                # Verify PKCE code verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                hashed_code_verifier = base64.urlsafe_b64encode(sha256).decode().rstrip("=")

                if hashed_code_verifier != auth_code.code_challenge:
                    # see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="incorrect code_verifier",
                        )
                    )

                try:
                    # Exchange authorization code for tokens
                    tokens = await self.provider.exchange_authorization_code(client_info, auth_code)
                except TokenError as e:
                    return self.response(
                        TokenErrorResponse(
                            error=e.error,
                            error_description=e.error_description,
                        )
                    )

            case RefreshTokenRequest():
                refresh_token = await self.provider.load_refresh_token(client_info, token_request.refresh_token)
                if refresh_token is None or refresh_token.client_id != token_request.client_id:
                    # if token belongs to different client, pretend it doesn't exist
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token does not exist",
                        )
                    )

                if refresh_token.expires_at and refresh_token.expires_at < time.time():
                    # if the refresh token has expired, pretend it doesn't exist
                    return self.response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token has expired",
                        )
                    )

                # Parse scopes if provided
                scopes = token_request.scope.split(" ") if token_request.scope else refresh_token.scopes

                for scope in scopes:
                    if scope not in refresh_token.scopes:
                        return self.response(
                            TokenErrorResponse(
                                error="invalid_scope",
                                error_description=(f"cannot request scope `{scope}` not provided by refresh token"),
                            )
                        )

                try:
                    # Exchange refresh token for new tokens
                    tokens = await self.provider.exchange_refresh_token(client_info, refresh_token, scopes)
                except TokenError as e:
                    return self.response(
                        TokenErrorResponse(
                            error=e.error,
                            error_description=e.error_description,
                        )
                    )

        return self.response(TokenSuccessResponse(root=tokens))
