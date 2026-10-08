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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.minidev.json.JSONObject;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * The claims of a JWT holding a Signature Request Parameter that is passed as a custom request parameter, see sections
 * 3.1.1.1 and 3.1.2 of
 * <a href="https://www.oidc.se/specifications/oidc-signature-extension-1_2.html">Signature Extension for OpenID
 * Connect, version 1.2</a>.
 * <p>
 * The JWT holds the fields of the {@link SignRequest} as top-level claims together with the {@code iss} (client ID) and
 * {@code aud} claims, and optionally the {@code iat} and {@code exp} claims.
 * </p>
 * <p>
 * Note: If the signature request parameter is passed in a Request Object, this class is not used. In that case the
 * Request Object holds the {@code iss}, {@code aud}, {@code iat} and {@code exp} claims, and the parameter value is a
 * {@link SignRequest} JSON object.
 * </p>
 *
 * @author Martin Lindström
 */
public class SignRequestClaimsSet {

  /** The client ID of the Relying Party (the {@code iss} claim). */
  private final ClientID clientId;

  /** The audience (the {@code aud} claim). */
  private final List<Audience> audience;

  /** The issue time (the {@code iat} claim). */
  private final Instant issueTime;

  /** The expiration time (the {@code exp} claim). */
  private final Instant expirationTime;

  /** The sign request. */
  private final SignRequest signRequest;

  /**
   * Constructor.
   * <p>
   * Since JWT times have second precision, the supplied times are truncated to seconds.
   * </p>
   *
   * @param clientId the client ID of the Relying Party, used as the {@code iss} claim
   * @param audience the audience, i.e., the Issuer Identifier or Authorization Endpoint URL of the OpenID Provider
   * @param issueTime the issue time ({@code iat}), may be {@code null}, but is recommended
   * @param expirationTime the expiration time ({@code exp}), may be {@code null}, but is recommended
   * @param signRequest the sign request
   */
  public SignRequestClaimsSet(final ClientID clientId, final Audience audience, final Instant issueTime,
      final Instant expirationTime, final SignRequest signRequest) {
    this(clientId, List.of(Objects.requireNonNull(audience, "audience must not be null")), issueTime, expirationTime,
        signRequest);
  }

  /**
   * Constructor.
   * <p>
   * Since JWT times have second precision, the supplied times are truncated to seconds.
   * </p>
   *
   * @param clientId the client ID of the Relying Party, used as the {@code iss} claim
   * @param audience the audience values (at least one)
   * @param issueTime the issue time ({@code iat}), may be {@code null}, but is recommended
   * @param expirationTime the expiration time ({@code exp}), may be {@code null}, but is recommended
   * @param signRequest the sign request
   */
  public SignRequestClaimsSet(final ClientID clientId, final List<Audience> audience, final Instant issueTime,
      final Instant expirationTime, final SignRequest signRequest) {
    this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
    this.audience = List.copyOf(Objects.requireNonNull(audience, "audience must not be null"));
    if (this.audience.isEmpty()) {
      throw new IllegalArgumentException("audience must not be empty");
    }
    this.issueTime = issueTime != null ? issueTime.truncatedTo(ChronoUnit.SECONDS) : null;
    this.expirationTime = expirationTime != null ? expirationTime.truncatedTo(ChronoUnit.SECONDS) : null;
    this.signRequest = Objects.requireNonNull(signRequest, "signRequest must not be null");
  }

  /**
   * Gets the client ID of the Relying Party (the {@code iss} claim).
   *
   * @return the client ID
   */
  public ClientID getClientID() {
    return this.clientId;
  }

  /**
   * Gets the audience (the {@code aud} claim).
   *
   * @return the audience values
   */
  public List<Audience> getAudience() {
    return this.audience;
  }

  /**
   * Gets the issue time (the {@code iat} claim).
   *
   * @return the issue time, or {@code null} if not set
   */
  public Instant getIssueTime() {
    return this.issueTime;
  }

  /**
   * Gets the expiration time (the {@code exp} claim).
   *
   * @return the expiration time, or {@code null} if not set
   */
  public Instant getExpirationTime() {
    return this.expirationTime;
  }

  /**
   * Gets the sign request.
   *
   * @return the sign request
   */
  public SignRequest getSignRequest() {
    return this.signRequest;
  }

  /**
   * Returns the {@link JWTClaimsSet} representation.
   *
   * @return a {@link JWTClaimsSet}
   */
  public JWTClaimsSet toJWTClaimsSet() {
    final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
        .issuer(this.clientId.getValue())
        .audience(Audience.toStringList(this.audience));
    if (this.issueTime != null) {
      builder.issueTime(Date.from(this.issueTime));
    }
    if (this.expirationTime != null) {
      builder.expirationTime(Date.from(this.expirationTime));
    }
    this.signRequest.toJSONObject().forEach(builder::claim);
    return builder.build();
  }

  /**
   * Creates a signed JWT holding the claims. The result should be serialized and used as the value of the
   * {@code https://id.oidc.se/param/signRequest} request parameter.
   *
   * @param signer the signer, using the client's registered key
   * @param header the JWS header
   * @return a signed JWT
   * @throws JOSEException for signing errors
   */
  public SignedJWT sign(final JWSSigner signer, final JWSHeader header) throws JOSEException {
    final SignedJWT jwt = new SignedJWT(
        Objects.requireNonNull(header, "header must not be null"), this.toJWTClaimsSet());
    jwt.sign(Objects.requireNonNull(signer, "signer must not be null"));
    return jwt;
  }

  /**
   * Parses the supplied {@link JWTClaimsSet} into a {@link SignRequestClaimsSet}.
   * <p>
   * Note: This method does not check the signature, the audience or the validity time of the JWT. Use
   * {@link SignRequestClaimsVerifier} for this.
   * </p>
   *
   * @param claimsSet the claims set
   * @return a {@link SignRequestClaimsSet}
   * @throws ParseException if required claims are missing, or for invalid sign request contents
   */
  public static SignRequestClaimsSet parse(final JWTClaimsSet claimsSet) throws ParseException {
    final String issuer = claimsSet.getIssuer();
    if (issuer == null) {
      throw new ParseException("Missing required claim iss");
    }
    final List<String> audience = claimsSet.getAudience();
    if (audience == null || audience.isEmpty()) {
      throw new ParseException("Missing required claim aud");
    }
    final Date issueTime = claimsSet.getIssueTime();
    final Date expirationTime = claimsSet.getExpirationTime();
    final SignRequest signRequest = SignRequest.parse(new JSONObject(claimsSet.toJSONObject()));

    return new SignRequestClaimsSet(new ClientID(issuer), Audience.create(audience),
        issueTime != null ? issueTime.toInstant() : null,
        expirationTime != null ? expirationTime.toInstant() : null,
        signRequest);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.clientId, this.audience, this.issueTime, this.expirationTime, this.signRequest);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if ((obj == null) || (this.getClass() != obj.getClass())) {
      return false;
    }
    final SignRequestClaimsSet other = (SignRequestClaimsSet) obj;
    return Objects.equals(this.clientId, other.clientId) && Objects.equals(this.audience, other.audience)
        && Objects.equals(this.issueTime, other.issueTime) && Objects.equals(this.expirationTime, other.expirationTime)
        && Objects.equals(this.signRequest, other.signRequest);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "iss=" + this.clientId + ", aud=" + this.audience
        + ", iat=" + (this.issueTime != null ? this.issueTime : "not-set")
        + ", exp=" + (this.expirationTime != null ? this.expirationTime : "not-set")
        + ", " + this.signRequest;
  }

}
