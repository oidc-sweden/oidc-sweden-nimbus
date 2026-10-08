/*
 * Copyright 2023-2026 OIDC Sweden
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
package se.oidc.nimbus.signrequest;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;
import se.oidc.nimbus.claims.ParameterConstants;

import java.util.List;
import java.util.Map;

/**
 * Utility methods for getting the {@code https://id.oidc.se/param/signRequest} parameter from an authentication
 * request. See section 3.1.1 of
 * <a href="https://www.oidc.se/specifications/oidc-signature-extension-1_2.html">Signature Extension for OpenID
 * Connect, version 1.2</a>.
 *
 * @author Martin Lindström
 */
public final class SignRequestParameterUtils {

  /**
   * Gets the signature request parameter JWT passed as a custom request parameter (section 3.1.1.1).
   * <p>
   * The returned JWT is either signed or signed and encrypted. The caller must decrypt it (if needed), verify its
   * signature and claims (see {@link SignRequestClaimsVerifier}), and then parse the claims using
   * {@link SignRequestClaimsSet#parse(com.nimbusds.jwt.JWTClaimsSet)}.
   * </p>
   *
   * @param request the authentication request
   * @return the JWT, or {@code null} if the request does not contain the parameter
   * @throws ParseException if the parameter value is not a valid JWT, is an unsigned JWT, or if the parameter is
   *     given more than once
   */
  public static JWT getSignRequestJWT(final AuthorizationRequest request) throws ParseException {
    final List<String> values = request.getCustomParameter(ParameterConstants.SIGN_REQUEST_PARAM_NAME);
    if (values == null || values.isEmpty()) {
      return null;
    }
    if (values.size() > 1) {
      throw new ParseException("Multiple values for " + ParameterConstants.SIGN_REQUEST_PARAM_NAME);
    }
    final JWT jwt;
    try {
      jwt = JWTParser.parse(values.get(0));
    }
    catch (final java.text.ParseException e) {
      throw new ParseException("Invalid JWT for " + ParameterConstants.SIGN_REQUEST_PARAM_NAME, e);
    }
    if (jwt instanceof PlainJWT) {
      throw new ParseException("Unsigned JWT for " + ParameterConstants.SIGN_REQUEST_PARAM_NAME + " is not allowed");
    }
    return jwt;
  }

  /**
   * Gets the signature request parameter from the claims of a Request Object (section 3.1.1.2).
   * <p>
   * The caller must have verified the Request Object before calling this method.
   * </p>
   *
   * @param requestObjectClaims the claims of a verified Request Object
   * @return the sign request, or {@code null} if the Request Object does not contain the parameter
   * @throws ParseException if the parameter value is invalid
   */
  public static SignRequest getSignRequest(final JWTClaimsSet requestObjectClaims) throws ParseException {
    final Object value = requestObjectClaims.getClaim(ParameterConstants.SIGN_REQUEST_PARAM_NAME);
    if (value == null) {
      return null;
    }
    if (value instanceof JSONObject jsonObject) {
      return SignRequest.parse(jsonObject);
    }
    if (value instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked") final Map<String, ?> m = (Map<String, ?>) map;
      return SignRequest.parse(new JSONObject(m));
    }
    throw new ParseException("Invalid type for " + ParameterConstants.SIGN_REQUEST_PARAM_NAME);
  }

  private SignRequestParameterUtils() {
  }

}
