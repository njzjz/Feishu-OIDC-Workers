/**
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1
 */
export type OAuth2AccessTokenType = "Bearer" | "MAC" | string;

/**
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
 */
export type OAuth2Authentication = {
  /**
   * The client identifier issued to the client during the registration process described by [Client Indentifier](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.2).
   */
  client_id: string;
  /**
   * The client secret.
   * The client MAY omit the parameter if the client secret is an empty string.
   */
  client_secret: string;
};

/**
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3
 */
export type OAuth2AccessTokenRequest = {
  grant_type: 'authorization_code';
  /** The authorization code received from the authorization server. */
  code: string;
  /**
   * REQUIRED, if the `redirect_uri` parameter was included in the authorization request as described in [Authorization Request](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1),
   * and their values MUST be identical.
   */
  redirect_uri?: string;
  /**
   * REQUIRED, if the client is not authenticating with the authorization server as described in [Client Authentication](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1).
   */
  client_id?: string;
};

export type OAuth2AccessTokenRequestWithAuth = OAuth2Authentication & OAuth2AccessTokenRequest;

// export type OAuth2AccessTokenRequest = (OAuth2Authentication & OAuth2AccessTokenRequestPure) | OAuth2AccessTokenRequestPure;

/**
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
 * @example
 * ```http
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 * ```
 * ```json
 * {
 *   "access_token":"2YotnFZFEjr1zCsicMWpAA",
 *   "token_type":"example",
 *   "expires_in":3600,
 *   "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
 *   "example_parameter":"example_value"
 * }
 * ```
 */
export type OAuth2AccessTokenSuccessResponse = {
  /** The access token issued by the authorization server. */
  access_token: string;
  /**
   * The type of the token issued as described in [Access Token Types](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1).
   * Value is case insensitive.
   */
  token_type: OAuth2AccessTokenType;
  /**
   * RECOMMENDED.
   * The lifetime in seconds of the access token.
   * For example, the value `3600` denotes that the access token will expire in one hour from the time the response was generated.
   * If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value.
   */
  expires_in: number;
  /**
   * OPTIONAL.
   * The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in [Refreshing an Access Token](https://www.rfc-editor.org/rfc/rfc6749.html#section-6).
   */
  refresh_token?: string;
  /**
   * OPTIONAL, if identical to the scope requested by the client;
   * otherwise, REQUIRED.
   *
   * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
   */
  scope?: string;
};

/**
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
 * @example
 * ```http
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 * ```
 * ```json
 * {
 *   "error":"invalid_request"
 * }
 * ```
 */
export type OAuth2AccessTokenErrorResponse = {
  /**
   * A single ASCII [USASCII] error code from the following:
   * - **invalid_request**:
   * The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.
   *
   * - **invalid_client**:
   * Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
   * The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
   * If the client attempted to authenticate via the `Authorization` request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the `WWW-Authenticate` response header field matching the authentication scheme used by the client.
   *
   * - **invalid_grant**:
   * The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token
   * is invalid, expired, revoked, does not match the redirection URI used in the authorization request,
   * or was issued to another client.
   *
   * - **unauthorized_client**:
   * The authenticated client is not authorized to use this authorization grant type.
   *
   * - **unsupported_grant_type**:
   * The authorization grant type is not supported by the authorization server.
   *
   * - **invalid_scope**:
   * The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
   *
   * Values for the `error` parameter MUST NOT include characters
   * outside the set %x20-21 / %x23-5B / %x5D-7E.
   */
  error: "invalid_request" | "invalid_client" | "invalid_grant" | "unauthorized_client" | "unsupported_grant_type" | "invalid_scope";

  /**
   * Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.
   *
   * Values for the `error_description` parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
   */
  error_description?: string;

  /**
   * A URI identifying a human-readable web page with information about the error,
   * used to provide the client developer with additional information about the error.
   * Values for the `error_uri` parameter MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.
   */
  error_uri?: string;
};

export type OAuth2AccessTokenResponse = OAuth2AccessTokenSuccessResponse | OAuth2AccessTokenErrorResponse;
