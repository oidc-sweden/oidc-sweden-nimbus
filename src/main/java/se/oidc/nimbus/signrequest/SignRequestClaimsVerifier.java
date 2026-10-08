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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Claims verifier for a signed JWT holding a Signature Request Parameter that is passed as a custom request parameter,
 * according to sections 3.1.2 and 5.1 of
 * <a href="https://www.oidc.se/specifications/oidc-signature-extension-1_2.html">Signature Extension for OpenID
 * Connect, version 1.2</a>. The verifier asserts that:
 * <ul>
 * <li>the {@code iss} claim is present and equals the client ID of the requesting client,</li>
 * <li>the {@code aud} claim is present and holds one of the accepted audience values, i.e., the Issuer Identifier of
 * the OpenID Provider or the Authorization Endpoint URL on which the request was received,</li>
 * <li>the JWT has not expired, if the {@code exp} claim is present,</li>
 * <li>the JWT was not issued too far in the past, if the {@code iat} claim is present and a maximum age has been set
 * using {@link #setMaxAge(Duration)}.</li>
 * </ul>
 * <p>
 * The verifier can be installed in a Nimbus {@code JWTProcessor} that also verifies the JWT signature.
 * </p>
 *
 * @param <C> the security context type
 * @author Martin Lindström
 */
public class SignRequestClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {

  /** The maximum allowed age of the JWT, based on the {@code iat} claim. */
  private Duration maxAge;

  /**
   * Constructor.
   *
   * @param clientId the client ID of the requesting client
   * @param acceptedAudience the accepted audience values
   */
  public SignRequestClaimsVerifier(final ClientID clientId, final Set<Audience> acceptedAudience) {
    super(toStringSet(acceptedAudience),
        new JWTClaimsSet.Builder()
            .issuer(Objects.requireNonNull(clientId, "clientId must not be null").getValue())
            .build(),
        Set.of(JWTClaimNames.ISSUER, JWTClaimNames.AUDIENCE),
        null);
  }

  /**
   * Constructor setting up the accepted audience values from the OpenID Provider Issuer Identifier and the
   * Authorization Endpoint URL.
   *
   * @param clientId the client ID of the requesting client
   * @param opIssuer the Issuer Identifier of the OpenID Provider
   * @param authorizationEndpoint the Authorization Endpoint URL on which the request was received, may be
   *     {@code null}
   */
  public SignRequestClaimsVerifier(final ClientID clientId, final Issuer opIssuer, final URI authorizationEndpoint) {
    this(clientId, toAudienceSet(opIssuer, authorizationEndpoint));
  }

  /**
   * Sets the maximum allowed age of the JWT. If set, and the JWT contains the {@code iat} claim, a JWT that was issued
   * longer ago than this (plus the allowed clock skew) is rejected. The default is {@code null}, meaning no check.
   *
   * @param maxAge the maximum age, or {@code null} for no check
   */
  public void setMaxAge(final Duration maxAge) {
    this.maxAge = maxAge;
  }

  /**
   * Gets the maximum allowed age of the JWT.
   *
   * @return the maximum age, or {@code null} if not set
   */
  public Duration getMaxAge() {
    return this.maxAge;
  }

  /** {@inheritDoc} */
  @Override
  public void verify(final JWTClaimsSet claimsSet, final C context) throws BadJWTException {
    super.verify(claimsSet, context);

    if (this.maxAge != null) {
      final Date issueTime = claimsSet.getIssueTime();
      final Date now = this.currentTime();
      if (issueTime != null && now != null) {
        final Instant oldestAllowed = now.toInstant().minus(this.maxAge).minusSeconds(this.getMaxClockSkew());
        if (issueTime.toInstant().isBefore(oldestAllowed)) {
          throw new BadJWTException("JWT was issued too far in the past");
        }
      }
    }
  }

  /**
   * Converts the audience set into a string set.
   *
   * @param audience the audience values
   * @return a set of strings
   */
  private static Set<String> toStringSet(final Set<Audience> audience) {
    Objects.requireNonNull(audience, "acceptedAudience must not be null");
    if (audience.isEmpty()) {
      throw new IllegalArgumentException("acceptedAudience must not be empty");
    }
    return audience.stream().map(Audience::getValue).collect(Collectors.toUnmodifiableSet());
  }

  /**
   * Builds the set of accepted audience values.
   *
   * @param opIssuer the OP Issuer Identifier
   * @param authorizationEndpoint the Authorization Endpoint URL, may be {@code null}
   * @return a set of audience values
   */
  private static Set<Audience> toAudienceSet(final Issuer opIssuer, final URI authorizationEndpoint) {
    final Set<Audience> audience = new HashSet<>();
    audience.add(new Audience(Objects.requireNonNull(opIssuer, "opIssuer must not be null")));
    if (authorizationEndpoint != null) {
      audience.add(new Audience(authorizationEndpoint));
    }
    return audience;
  }

}
