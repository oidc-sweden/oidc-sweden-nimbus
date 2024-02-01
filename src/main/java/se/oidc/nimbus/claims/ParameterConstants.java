/*
 * Copyright 2023-2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.nimbus.claims;

/**
 * Representation of the request parameter names defined within the OIDC Sweden specifications.
 *
 * @author Martin Lindström
 */
public class ParameterConstants {

  /** Prefix for parameters defined by OIDC Sweden. */
  public static final String OIDC_SWEDEN_PARAM_PREFIX = "https://id.oidc.se/param/";

  /** Prefix for disovery parameters defined by OIDC Sweden. */
  public static final String OIDC_SWEDEN_DISCO_PREFIX = "https://id.oidc.se/disco/";

  /**
   * When the user message claim is included in an authentication request, the issuing client requests that the OpenID
   * Provider displays this message to the client in conjunction with the user authentication.
   */
  public static final String USER_MESSAGE_PARAM_NAME = OIDC_SWEDEN_PARAM_PREFIX + "userMessage";

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the
   * {@code https://id.oidc.se/param/userMessage} authentication request parameter.
   */
  public static final String USER_MESSAGE_SUPPORTED_PARAM_NAME = OIDC_SWEDEN_DISCO_PREFIX + "userMessageSupported";

  /**
   * Holds the User Message MIME type(s) that is supported by the OpenID Provider. Its value is only relevant if
   * {@code https://id.oidc.se/disco/userMessageSupported} is set to {@code true}.
   */
  public static final String USER_MESSAGE_SUPPORTED_MIMETYPES_PARAM_NAME =
      OIDC_SWEDEN_DISCO_PREFIX + "userMessageSupportedMimeTypes";

  /**
   * In cases where the OpenID Provider can delegate, or proxy, the user authentication to multiple authentication
   * services, or if the OP offers multiple authentication mechanisms, the {@code authnProvider} request parameter MAY
   * be used to inform the OP about which of the authentication services, or mechanisms, that the Relying Party requests
   * the user to be authenticated at/with.
   */
  public static final String REQUESTED_PROVIDER_PARAM_NAME = OIDC_SWEDEN_PARAM_PREFIX + "authnProvider";

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the
   * {@code https://id.oidc.se/param/authnProvider} authentication request parameter.
   */
  public static final String REQUESTED_PROVIDER_SUPPORTED_PARAM_NAME =
      OIDC_SWEDEN_DISCO_PREFIX + "authnProviderSupported";

  /**
   * Contains the client identifier for the client that requested authentication from a proxy authentication service.
   * This ID is generally not the same as {@code client_id} which is the ID for the client communicating with the OP.
   */
  public static final String ORIGINAL_CLIENT_ID_PARAM_NAME = OIDC_SWEDEN_PARAM_PREFIX + "originalClientId";

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the
   * {@code https://id.oidc.se/param/originalClientId} authentication request parameter.
   */
  public static final String ORIGINAL_CLIENT_ID_SUPPORTED_PARAM_NAME =
      OIDC_SWEDEN_DISCO_PREFIX + "originalClientIdSupported";

  /**
   * A token containing information about the the client that requested authentication from a proxy authentication
   * service.
   */
  public static final String ORIGINAL_CLIENT_TOKEN_PARAM_NAME = OIDC_SWEDEN_PARAM_PREFIX + "originalClientToken";

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the
   * {@code https://id.oidc.se/param/originalClientToken} authentication request parameter.
   */
  public static final String ORIGINAL_CLIENT_TOKEN_SUPPORTED_PARAM_NAME =
      OIDC_SWEDEN_DISCO_PREFIX + "originalClientTokenSupported";

  /**
   * The signature request parameter is included in an authentication request by the Relying Party in order to request a
   * user signature. The signature request parameter contains input for this signature operation.
   */
  public static final String SIGN_REQUEST_PARAM_NAME = OIDC_SWEDEN_PARAM_PREFIX + "signRequest";

  // Hidden
  private ParameterConstants() {
  }

}
