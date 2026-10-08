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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.ExpiredJWTException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.oidc.nimbus.usermessage.UserMessage;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Test cases for SignRequestClaimsVerifier.
 *
 * @author Martin Lindström
 */
public class SignRequestClaimsVerifierTest {

  private static final ClientID CLIENT_ID = new ClientID("https://client.example.com");

  private static final Issuer OP_ISSUER = new Issuer("https://server.example.com");

  private static final URI AUTHZ_ENDPOINT = URI.create("https://server.example.com/authorize");

  private static final SignRequest SIGN_REQUEST = new SignRequest("This is the text to sign".getBytes(),
      new UserMessage(List.of(new UserMessage.Message("Approve signature", "en")), UserMessage.TEXT_MIME_TYPE));

  private final SignRequestClaimsVerifier<SecurityContext> verifier =
      new SignRequestClaimsVerifier<>(CLIENT_ID, OP_ISSUER, AUTHZ_ENDPOINT);

  @Test
  public void testValid() throws Exception {
    final Instant now = Instant.now();
    this.verifier.verify(claims(new Audience(OP_ISSUER), now, now.plusSeconds(300)), null);
    this.verifier.verify(claims(new Audience(AUTHZ_ENDPOINT), now, now.plusSeconds(300)), null);
    this.verifier.verify(claims(new Audience(OP_ISSUER), null, null), null);
  }

  @Test
  public void testIssuer() {
    final JWTClaimsSet wrongIss = new JWTClaimsSet.Builder(claims(new Audience(OP_ISSUER), null, null))
        .issuer("https://other.example.com")
        .build();
    Assertions.assertEquals("JWT iss claim value rejected",
        Assertions.assertThrows(BadJWTException.class, () -> this.verifier.verify(wrongIss, null)).getMessage());

    final JWTClaimsSet noIss = new JWTClaimsSet.Builder(claims(new Audience(OP_ISSUER), null, null))
        .issuer(null)
        .build();
    Assertions.assertThrows(BadJWTException.class, () -> this.verifier.verify(noIss, null));
  }

  @Test
  public void testAudience() {
    final JWTClaimsSet wrongAud = claims(new Audience("https://other.example.com"), null, null);
    Assertions.assertEquals("JWT aud claim rejected",
        Assertions.assertThrows(BadJWTException.class, () -> this.verifier.verify(wrongAud, null)).getMessage());

    final JWTClaimsSet noAud = new JWTClaimsSet.Builder(claims(new Audience(OP_ISSUER), null, null))
        .audience((String) null)
        .build();
    Assertions.assertThrows(BadJWTException.class, () -> this.verifier.verify(noAud, null));

    final SignRequestClaimsVerifier<SecurityContext> issuerOnly =
        new SignRequestClaimsVerifier<>(CLIENT_ID, OP_ISSUER, null);
    Assertions.assertThrows(BadJWTException.class,
        () -> issuerOnly.verify(claims(new Audience(AUTHZ_ENDPOINT), null, null), null));
  }

  @Test
  public void testExpired() {
    final Instant now = Instant.now();
    Assertions.assertThrows(ExpiredJWTException.class, () -> this.verifier.verify(
        claims(new Audience(OP_ISSUER), now.minusSeconds(600), now.minusSeconds(300)), null));
  }

  @Test
  public void testMaxAge() throws Exception {
    final Instant now = Instant.now();
    final JWTClaimsSet oldClaims = claims(new Audience(OP_ISSUER), now.minusSeconds(600), null);

    // No max age set, so iat is not checked
    Assertions.assertNull(this.verifier.getMaxAge());
    this.verifier.verify(oldClaims, null);

    final SignRequestClaimsVerifier<SecurityContext> v =
        new SignRequestClaimsVerifier<>(CLIENT_ID, Set.of(new Audience(OP_ISSUER)));
    v.setMaxAge(Duration.ofMinutes(5));
    Assertions.assertEquals(Duration.ofMinutes(5), v.getMaxAge());
    Assertions.assertEquals("JWT was issued too far in the past",
        Assertions.assertThrows(BadJWTException.class, () -> v.verify(oldClaims, null)).getMessage());

    // Within max age plus clock skew
    v.verify(claims(new Audience(OP_ISSUER), now.minusSeconds(320), null), null);

    // No iat, nothing to check
    v.verify(claims(new Audience(OP_ISSUER), null, null), null);
  }

  @Test
  public void testWithJWTProcessor() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_256).keyID("client-sign-1").generate();
    final Instant now = Instant.now();
    final String jwt = new SignRequestClaimsSet(CLIENT_ID, new Audience(OP_ISSUER), now, now.plusSeconds(300),
        SIGN_REQUEST)
        .sign(new ECDSASigner(key), new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build())
        .serialize();

    final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256,
        new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK()))));
    processor.setJWTClaimsSetVerifier(this.verifier);

    final SignRequestClaimsSet claims = SignRequestClaimsSet.parse(processor.process(jwt, null));
    Assertions.assertEquals(SIGN_REQUEST, claims.getSignRequest());
  }

  @Test
  public void testConstructorErrors() {
    Assertions.assertThrows(NullPointerException.class,
        () -> new SignRequestClaimsVerifier<>(null, OP_ISSUER, AUTHZ_ENDPOINT));
    Assertions.assertThrows(NullPointerException.class,
        () -> new SignRequestClaimsVerifier<>(CLIENT_ID, null, AUTHZ_ENDPOINT));
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> new SignRequestClaimsVerifier<>(CLIENT_ID, Set.of()));
  }

  private static JWTClaimsSet claims(final Audience audience, final Instant iat, final Instant exp) {
    return new SignRequestClaimsSet(CLIENT_ID, audience, iat, exp, SIGN_REQUEST).toJWTClaimsSet();
  }

}
