import type {
  OAuth2AccessTokenSuccessResponse
} from "./oauth2";

/**
 * @see https://openid.net/specs/openid-connect-core-1_0.md#IDToken
 * @example
 * ```json
 * {
 *   "iss": "https://server.example.com",
 *   "sub": "24400320",
 *   "aud": "s6BhdRkqt3",
 *   "nonce": "n-0S6_WzA2Mj",
 *   "exp": 1311281970,
 *   "iat": 1311280970,
 *   "auth_time": 1311280969,
 *   "acr": "urn:mace:incommon:iap:silver"
 *  }
 * ```
 */
type OpenIDTokenStandard = {
  /**
   * Issuer Identifier for the Issuer of the response.
   * The `iss` value is a case-sensitive URL using the `https` scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
   */
  iss: string;
  /**
   * Subject Identifier.
   * A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., `24400320` or `AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4`.
   * It MUST NOT exceed 255 ASCII [RFC20] characters in length. The `sub` value is a case-sensitive string.
   */
  sub: string;
  /**
   * Audience(s) that this ID Token is intended for.
   * It MUST contain the OAuth 2.0 `client_id` of the Relying Party as an audience value.
   * It MAY also contain identifiers for other audiences.
   * In the general case, the `aud` value is an array of case-sensitive strings.
   * In the common special case when there is one audience, the `aud` value MAY be a single case-sensitive string.
   */
  aud: string;
  /**
   * Expiration time on or after which the ID Token MUST NOT be accepted by the RP when performing authentication with the OP.
   * The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
   * Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
   * Its value is a JSON [RFC8259] number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
   * See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
   * NOTE: The ID Token expiration time is unrelated the lifetime of the authenticated session between the RP and the OP.
   */
  exp: number;
  /**
   * Time at which the JWT was issued.
   * Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
   */
  iat: number;
  /**
   * Time when the End-User authentication occurred.
   * Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
   * When a `max_age` request is made or when `auth_time` is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
   * (The `auth_time` Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] `auth_time` response parameter.)
   */
  auth_time?: number;
  /**
   * String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
   * The value is passed through unmodified from the Authentication Request to the ID Token.
   * If present in the ID Token, Clients MUST verify that the `nonce` Claim Value is equal to the value of the `nonce` parameter sent in the Authentication Request.
   * If present in the Authentication Request, Authorization Servers MUST include a `nonce` Claim in the ID Token with the Claim Value being the `nonce` value sent in the Authentication Request.
   * Authorization Servers SHOULD perform no other processing on `nonce` values used.
   * The `nonce` value is a case-sensitive string.
   */
  nonce?: string;
  /**
   * Authentication Context Class Reference.
   * String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.
   * The value `"0"` indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1.
   * For historic reasons, the value `"0"` is used to indicate that there is no confidence that the same person is actually there.
   * Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value.
   * (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] `nist_auth_level` 0.)
   * An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the `acr` value; registered names MUST NOT be used with a different meaning than that which is registered.
   * Parties using this claim will need to agree upon the meanings of the values used, which may be context specific.
   * The `acr` value is a case-sensitive string.
   */
  acr?: string;
  /**
   * Authentication Methods References.
   * JSON array of strings that are identifiers for authentication methods used in the authentication.
   * For instance, values might indicate that both password and OTP authentication methods were used.
   * The `amr` value is an array of case-sensitive strings.
   * Values used in the `amr` Claim SHOULD be from those registered in the IANA Authentication Method Reference Values registry [IANA.AMR] established by [RFC8176];
   * parties using this claim will need to agree upon the meanings of any unregistered values used, which may be context specific.
   */
  amr?: string[];
  /**
   * Authorized party - the party to which the ID Token was issued.
   * If present, it MUST contain the OAuth 2.0 Client ID of this party.
   * The `azp` value is a case-sensitive string containing a StringOrURI value.
   * Note that in practice, the `azp` Claim only occurs when extensions beyond the scope of this specification are used; therefore, implementations not using such extensions are encouraged to not use `azp` and to ignore it when it does occur.
   */
  azp?: string;
};

export type OpenIDToken = OpenIDTokenStandard & Partial<OpenIDStandardClaims>;

/**
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 * @example
 * ```http
 * GET /authorize?
 *   response_type=code
 *   &scope=openid%20profile%20email
 *   &client_id=s6BhdRkqt3
 *   &state=af0ifjsldkj
 *   &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1
 * ```
 */
export type OpenIDAuthRequestParams = {
  /**
   * OpenID Connect requests MUST contain the `openid` scope value.
   * If the `openid` scope value is not present, the behavior is entirely unspecified.
   * Other scope values MAY be present.
   * Scope values used that are not understood by an implementation SHOULD be ignored.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
   * @see https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
   */
  scope: string;
  /**
   * OAuth 2.0 Response Type value that determines the authorization processing flow to be used, including what parameters are returned from the endpoints used.
   * When using the Authorization Code Flow, this value is `code`.
   */
  response_type: string;
  /**
   * OAuth 2.0 Client Identifier valid at the Authorization Server.
   */
  client_id: string;
  /**
   * Redirection URI to which the response will be sent.
   * This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
   * When using this flow, the Redirection URI SHOULD use the `https` scheme;
   * however, it MAY use the `http` scheme, provided that the Client Type is `confidential`, as defined in Section 2.1 of OAuth 2.0, and provided the OP allows the use of `http` Redirection URIs in this case.
   * Also, if the Client is a native application, it MAY use the `http` scheme with `localhost` or the IP loopback literals `127.0.0.1` or `[::1]` as the hostname.
   * The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application.
   */
  redirect_uri: string;
  /**
   * RECOMMENDED.
   * Opaque value used to maintain state between the request and the callback.
   * Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie.
   */
  state?: string;
  /**
   * Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.
   * This use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.
   */
  response_mode?: string;
  /**
   * String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
   * The value is passed through unmodified from the Authentication Request to the ID Token.
   * Sufficient entropy MUST be present in the `nonce` values used to prevent attackers from guessing values.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   */
  nonce?: string;
  /**
   * ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
   * The defined values are:
   * - page:
   *   The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view. If the display parameter is not specified, this is the default display mode.
   * - popup:
   *   The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window. The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
   * - touch:
   *   The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
   * - wap:
   *   The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
   *
   * The Authorization Server MAY also attempt to detect the capabilities of the User Agent and present an appropriate display.
   *
   * If an OP receives a `display` value outside the set defined above that it does not understand, it MAY return an error or it MAY ignore it;
   * in practice, not returning errors for not-understood values will help facilitate phasing in extensions using new `display` values.
   */
  display?: "page" | "popup" | "touch" | "wap";
  /**
   * Space-delimited, case-sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
   * The defined values are:
   * - none:
   * The Authorization Server MUST NOT display any authentication or consent user interface pages.
   * An error is returned if an End-User is not already authenticated or the Client does not have pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request.
   * The error code will typically be `login_required`, `interaction_required`, or another code defined in Section 3.1.2.6.
   * This can be used as a method to check for existing authentication and/or consent.
   * - login:
   *   The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot reauthenticate the End-User, it MUST return an error, typically `login_required`.
   * - consent:
   *   The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
   *   If it cannot obtain consent, it MUST return an error, typically `consent_required`.
   * - select_account:
   *   The Authorization Server SHOULD prompt the End-User to select a user account.
   *   This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple accounts that they might have current sessions for.
   *   If it cannot obtain an account selection choice made by the End-User, it MUST return an error, typically `account_selection_required`.
   *
   * The `prompt` parameter can be used by the Client to make sure that the End-User is still present for the current session or to bring attention to the request.
   * If this parameter contains `none` with any other value, an error is returned.
   *
   * If an OP receives a `prompt` value outside the set defined above that it does not understand, it MAY return an error or it MAY ignore it;
   * in practice, not returning errors for not-understood values will help facilitate phasing in extensions using new `prompt` values.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthError
   */
  prompt?: "none" | "login" | "consent" | "select_account";
  /**
   * Maximum Authentication Age.
   * Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
   * If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User.
   * (The `max_age` request parameter corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] `max_auth_age` request parameter.)
   * When `max_age` is used, the ID Token returned MUST include an `auth_time` Claim Value. Note that `max_age=0` is equivalent to `prompt=login`.
   */
  max_age?: number;
  /**
   * End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
   * For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation).
   * An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
   */
  ui_locales?: string;
  /**
   * ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client.
   * If the End-User identified by the ID Token is already logged in or is logged in as a result of the request (with the OP possibly evaluating other information beyond the ID Token in this decision),
   * then the Authorization Server returns a positive response; otherwise, it MUST return an error, such as `login_required`.
   * When possible, an `id_token_hint` SHOULD be present when `prompt=none` is used and an `invalid_request` error MAY be returned if it is not;
   * however, the server SHOULD respond successfully when possible, even if it is not present.
   * The Authorization Server need not be listed as an audience of the ID Token when it is used as an `id_token_hint` value.
   *
   * If the ID Token received by the RP from the OP is encrypted, to use it as an `id_token_hint`, the Client MUST decrypt the signed ID Token contained within the encrypted ID Token.
   * The Client MAY re-encrypt the signed ID token to the Authentication Server using a key that enables the server to decrypt the ID Token and use the re-encrypted ID token as the `id_token_hint` value.
   */
  id_token_hint?: string;
  /**
   * Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary).
   * This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service.
   * It is RECOMMENDED that the hint value match the value used for discovery.
   * This value MAY also be a phone number in the format specified for the `phone_number` Claim.
   * The use of this parameter is left to the OP's discretion.
   */
  login_hint?: string;
  /**
   * Requested Authentication Context Class Reference values.
   * Space-separated string that specifies the `acr` values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference.
   * The Authentication Context Class satisfied by the authentication performed is returned as the `acr` Claim Value, as specified in [ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
   * The `acr` Claim is requested as a Voluntary Claim by this parameter.
   */
  acr_values?: string;
};

export type OpenIDSuccessTokenResponse = OAuth2AccessTokenSuccessResponse & {
  /** ID Token value associated with the authenticated session. */
  id_token: string;
};

export type OpenIDStandardClaims = {
  /**
   * Subject - Identifier for the End-User at the Issuer.
   */
  sub: string;

  /**
   * End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
   */
  name: string;

  /**
   * Given name(s) or first name(s) of the End-User.
   * Note that in some cultures, people can have multiple given names;
   * all can be present, with the names being separated by space characters.
   */
  given_name: string;

  /**
   * Surname(s) or last name(s) of the End-User.
   * Note that in some cultures, people can have multiple family names or no family name;
   * all can be present, with the names being separated by space characters.
   */
  family_name: string;

  /**
   * Middle name(s) of the End-User.
   * Note that in some cultures, people can have multiple middle names;
   * all can be present, with the names being separated by space characters.
   * Also note that in some cultures, middle names are not used.
   */
  middle_name: string;

  /**
   * Casual name of the End-User that may or may not be the same as the `given_name`.
   * For instance, a `nickname` value of Mike might be returned alongside a `given_name` value of `Michael`.
   */
  nickname: string;

  /**
   * Shorthand name by which the End-User wishes to be referred to at the RP, such as `janedoe` or `j.doe`.
   * This value MAY be any valid JSON string including special characters such as `@`, `/`, or whitespace.
   * The RP MUST NOT rely upon this value being unique, as discussed in [Claim Stability and Uniqueness](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
   */
  preferred_username: string;

  /**
   * URL of the End-User's profile page.
   * The contents of this Web page SHOULD be about the End-User.
   */
  profile: string;

  /**
   * URL of the End-User's profile picture.
   * This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image.
   * Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
   */
  picture: string;

  /**
   * URL of the End-User's Web page or blog.
   * This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
   */
  website: string;

  /**
   * End-User's preferred e-mail address.
   * Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax.
   * The RP MUST NOT rely upon this value being unique, as discussed in [Claim Stability and Uniqueness](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
   */
  email: string;

  /**
   * True if the End-User's e-mail address has been verified; otherwise false.
   * When this Claim Value is `true`, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed.
   * The means by which an e-mail address is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
   */
  email_verified: boolean;

  /**
   * End-User's gender.
   * Values defined by this specification are `female` and `male`.
   * Other values MAY be used when neither of the defined values are applicable.
   */
  gender: "female" | "male" | string;

  /**
   * End-User's birthday, represented as an ISO 8601-1 [ISO8601‑1] `YYYY-MM-DD` format.
   * The year MAY be `0000`, indicating that it is omitted.
   * To represent only the year, `YYYY` format is allowed.
   * Note that depending on the underlying platform's date related function, providing just year can result in varying month and day,
   * so the implementers need to take this factor into account to correctly process the dates.
   */
  birthdate: string;

  /**
   * String from IANA Time Zone Database [IANA.time‑zones] representing the End-User's time zone.
   * For example, `Europe/Paris` or `America/Los_Angeles`.
   */
  zoneinfo: string;

  /**
   * End-User's locale, represented as a BCP47 [RFC5646] language tag.
   * This is typically an ISO 639 Alpha-2 [ISO639] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash.
   * For example, `en-US` or `fr-CA`.
   * As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, `en_US`;
   * Relying Parties MAY choose to accept this locale syntax as well.
   */
  locale: string;

  /**
   * End-User's preferred telephone number.
   * E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, `+1 (425) 555-1212` or `+56 (2) 687 2400`.
   * If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax,
   * for example, `+1 (604) 555-1234;ext=5678`.
   */
  phone_number: string;

  /**
   * True if the End-User's phone number has been verified; otherwise false.
   * When this Claim Value is `true`, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed.
   * The means by which a phone number is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
   * When `true`, the `phone_number` Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
   */
  phone_number_verified: boolean;

  /**
   * End-User's preferred postal address.
   * The value of the `address` member is a JSON [RFC8259] structure containing some or all of the members defined in [AddressClaim](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim).
   */
  address: OpenIDAddressClaim;

  /**
   * Time the End-User's information was last updated.
   * Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
   */
  updated_at: number;
};

type OpenIDAddressClaim = {
  /**
   * Full mailing address, formatted for display or use on a mailing label.
   * This field MAY contain multiple lines, separated by newlines.
   * Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
   */
  formatted: string;
  /**
   * Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information.
   * This field MAY contain multiple lines, separated by newlines.
   * Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
   */
  street_address: string;
  /** City or locality component. */
  locality: string;
  /** State, province, prefecture, or region component. */
  region: string;
  /** Zip code or postal code component. */
  postal_code: string;
  /** Country name component. */
  country: string;
}

export type OpenIDUserInfoSuccessResponse = {
  sub: string;
} & Partial<OpenIDStandardClaims>;
