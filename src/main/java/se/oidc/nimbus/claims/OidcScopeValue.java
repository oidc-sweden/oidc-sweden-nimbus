/*
 * Copyright 2023-2025 OIDC Sweden
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

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import se.oidc.nimbus.LibraryVersion;

import java.io.Serial;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

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

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Informs the authorization server that the client is making an OpenID Connect request (REQUIRED). This scope value
   * requests access to the {@code sub} claim.
   */
  public static final OidcScopeValue OPENID =
      new OidcScopeValue("openid", Scope.Value.Requirement.REQUIRED, new ClaimRequirement[] {
          ClaimRequirement.of("sub", true, true, true) });

  /**
   * Requests that access to the end-user's default profile claims at the UserInfo endpoint be granted by the issued
   * access token. These claims are: {@code name}, {@code family_name}, {@code given_name}, {@code middle_name},
   * {@code nickname}, {@code preferred_username}, {@code profile}, {@code picture}, {@code website}, {@code gender},
   * {@code birthdate}, {@code zoneinfo}, {@code locale}, and {@code updated_at}.
   */
  public static final OidcScopeValue PROFILE =
      new OidcScopeValue("profile", new ClaimRequirement[] {
          ClaimRequirement.of("name"),
          ClaimRequirement.of("family_name"),
          ClaimRequirement.of("given_name"),
          ClaimRequirement.of("middle_name"),
          ClaimRequirement.of("nickname"),
          ClaimRequirement.of("preferred_username"),
          ClaimRequirement.of("profile"),
          ClaimRequirement.of("picture"),
          ClaimRequirement.of("website"),
          ClaimRequirement.of("gender"),
          ClaimRequirement.of("birthdate"),
          ClaimRequirement.of("zoneinfo"),
          ClaimRequirement.of("locale"),
          ClaimRequirement.of("updated_at") });

  /**
   * Requests that access to the {@code email} and {@code email_verified} claims at the UserInfo endpoint be granted by
   * the issued access token.
   */
  public static final OidcScopeValue EMAIL = new OidcScopeValue("email", new ClaimRequirement[] {
      ClaimRequirement.of("email"), ClaimRequirement.of("email_verified") });

  /**
   * Requests that access to {@code address} claim at the UserInfo endpoint be granted by the issued access token.
   */
  public static final OidcScopeValue ADDRESS = new OidcScopeValue("address",
      new ClaimRequirement[] { ClaimRequirement.of("address") });

  /**
   * Requests that access to the {@code phone_number} and {@code phone_number_verified} claims at the UserInfo endpoint
   * be granted by the issued access token.
   */
  public static final OidcScopeValue PHONE = new OidcScopeValue("phone", new ClaimRequirement[] {
      ClaimRequirement.of("phone_number"), ClaimRequirement.of("phone_number_verified") });

  /**
   * Requests that an OAuth 2.0 refresh token be issued that can be used to obtain an access token that grants access
   * the end-user's UserInfo endpoint even when the user is not present (not logged in).
   */
  public static final OidcScopeValue OFFLINE_ACCESS = new OidcScopeValue("offline_access", null);

  /**
   * The names of the associated claims, {@code null} if not applicable.
   */
  private final Set<ClaimRequirement> claims;

  /**
   * Creates a new OpenID Connect scope value.
   *
   * @param value The scope value
   * @param requirement The requirement
   * @param claims the associated claims, {@code null} if not applicable.
   */
  public OidcScopeValue(final String value, final Scope.Value.Requirement requirement,
      final ClaimRequirement[] claims) {
    super(value, requirement);

    this.claims = claims != null
        ? Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(claims)))
        : null;
  }

  /**
   * Creates a new OpenID Connect scope value. The requirement is set to
   * {@link OIDCScopeValue.Requirement#OPTIONAL optional}.
   *
   * @param value the scope value
   * @param claims the associated claims
   */
  public OidcScopeValue(final String value, final ClaimRequirement[] claims) {
    this(value, Scope.Value.Requirement.OPTIONAL, claims);
  }

  /**
   * Returns the names of the associated claims.
   *
   * @return the names of the associated claims, {@code null} if not applicable.
   */
  public Set<String> getClaimNames() {
    return this.claims != null
        ? this.claims.stream().map(c -> c.name).collect(Collectors.toSet())
        : null;
  }

  /**
   * Returns the associated claims.
   *
   * @return the associated claims, or {@code null} if not applicable
   */
  public Set<ClaimRequirement> getClaimRequirements() {
    return this.claims;
  }

  /**
   * Representation of the claim requirement within a scope.
   * <p>
   * The {@code name} parameter holds the claim name. The {@code essential} tells whether the claim should be seen as
   * "essential". The {@code defaultIdTokenDelivery} and {@code defaultUserInfoDelivery} tells whether the default
   * delivery is via ID Token or UserInfo endpoint respectively. Note that both may be set to {@code true}, but both can
   * not be set to {@code false}.
   * </p>
   */
  public record ClaimRequirement(String name, boolean essential,
      boolean defaultIdTokenDelivery, boolean defaultUserInfoDelivery) {

    public ClaimRequirement {
      if (!defaultIdTokenDelivery && !defaultUserInfoDelivery) {
        throw new IllegalArgumentException("At least one default delivery option must be set");
      }
    }

    /**
     * Creates a requirement where the claim is not essential and the default delivery is from the UserInfo endpoint.
     *
     * @param name the claim name
     * @return a {@link ClaimRequirement}
     */
    public static ClaimRequirement of(final String name) {
      return new ClaimRequirement(name, false, false, true);
    }

    /**
     * Creates a {@link ClaimRequirement}.
     *
     * @param name the claim name
     * @param essential whether the claim is essential
     * @param defaultIdTokenDelivery whether to deliver in ID Token by default
     * @param defaultUserInfoDelivery whether to deliver from UserInfo endpoint by default
     * @return a {@link ClaimRequirement}
     */
    public static ClaimRequirement of(final String name, final boolean essential,
        final boolean defaultIdTokenDelivery, final boolean defaultUserInfoDelivery) {
      return new ClaimRequirement(name, essential, defaultIdTokenDelivery, defaultUserInfoDelivery);

    }
  }

}
