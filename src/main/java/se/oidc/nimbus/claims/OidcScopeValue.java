/*
 * Copyright 2023 OIDC Sweden
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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import se.oidc.nimbus.LibraryVersion;

/**
 * Representation of an OpenID Connect scope value.
 * <p>
 * This is more or less a copy of {@link OIDCScopeValue}, but that class has a private constructor and we want to be
 * able to declare also non-standard/private scopes.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcScopeValue extends Scope.Value {

  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Informs the authorization server that the client is making an OpenID Connect request (REQUIRED). This scope value
   * requests access to the {@code sub} claim.
   */
  public static final OidcScopeValue OPENID =
      new OidcScopeValue("openid", Scope.Value.Requirement.REQUIRED, new String[] { "sub" });

  /**
   * Requests that access to the end-user's default profile claims at the UserInfo endpoint be granted by the issued
   * access token. These claims are: {@code name}, {@code family_name}, {@code given_name}, {@code middle_name},
   * {@code nickname}, {@code preferred_username}, {@code profile}, {@code picture}, {@code website}, {@code gender},
   * {@code birthdate}, {@code zoneinfo}, {@code locale}, and {@code updated_at}.
   */
  public static final OidcScopeValue PROFILE =
      new OidcScopeValue("profile", new String[] { 
          "name",
          "family_name",
          "given_name",
          "middle_name",
          "nickname",
          "preferred_username",
          "profile",
          "picture",
          "website",
          "gender",
          "birthdate",
          "zoneinfo",
          "locale",
          "updated_at" });

  /**
   * Requests that access to the {@code email} and {@code email_verified} claims at the UserInfo endpoint be granted by
   * the issued access token.
   */
  public static final OidcScopeValue EMAIL =
      new OidcScopeValue("email", new String[] { "email", "email_verified" });

  /**
   * Requests that access to {@code address} claim at the UserInfo endpoint be granted by the issued access token.
   */
  public static final OidcScopeValue ADDRESS =
      new OidcScopeValue("address", new String[] { "address" });

  /**
   * Requests that access to the {@code phone_number} and {@code phone_number_verified} claims at the UserInfo endpoint
   * be granted by the issued access token.
   */
  public static final OidcScopeValue PHONE =
      new OidcScopeValue("phone", new String[] { "phone_number", "phone_number_verified" });

  /**
   * Requests that an OAuth 2.0 refresh token be issued that can be used to obtain an access token that grants access
   * the end-user's UserInfo endpoint even when the user is not present (not logged in).
   */
  public static final OidcScopeValue OFFLINE_ACCESS =
      new OidcScopeValue("offline_access", null);

  /**
   * The names of the associated claims, {@code null} if not applicable.
   */
  private final Set<String> claims;

  /**
   * Creates a new OpenID Connect scope value.
   *
   * @param value The scope value
   * @param requirement The requirement
   * @param claims the names of the associated claims, {@code null} if not applicable.
   */
  public OidcScopeValue(final String value, final Scope.Value.Requirement requirement, final String[] claims) {
    super(value, requirement);

    this.claims = claims != null
        ? Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(claims)))
        : null;
  }

  /**
   * Creates a new OpenID Connect scope value. The requirement is set to {@link OIDCScopeValue.Requirement#OPTIONAL
   * optional}.
   *
   * @param value the scope value
   * @param claims the names of the associated claims
   */
  public OidcScopeValue(final String value, final String[] claims) {
    this(value, Scope.Value.Requirement.OPTIONAL, claims);
  }

  /**
   * Returns the names of the associated claims.
   *
   * @return the names of the associated claims, {@code null} if not applicable.
   */
  public Set<String> getClaimNames() {
    return this.claims;
  }

}
