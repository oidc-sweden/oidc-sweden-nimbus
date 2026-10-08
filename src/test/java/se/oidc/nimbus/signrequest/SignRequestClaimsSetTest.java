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
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.oidc.nimbus.usermessage.UserMessage;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

/**
 * Test cases for SignRequestClaimsSet.
 *
 * @author Martin Lindström
 */
public class SignRequestClaimsSetTest {

  private static final ClientID CLIENT_ID = new ClientID("https://client.example.com");

  private static final Audience AUDIENCE = new Audience("https://server.example.com");

  private static final UserMessage SIGN_MESSAGE = new UserMessage(List.of(
      new UserMessage.Message("Godkänn underskrift", "sv"),
      new UserMessage.Message("Approve signature", "en")),
      UserMessage.TEXT_MIME_TYPE);

  @Test
  public void testCreateAndGet() {
    final Instant now = Instant.now();
    final SignRequest signRequest = new SignRequest("This is the text to sign".getBytes(), SIGN_MESSAGE);
    final SignRequestClaimsSet claims =
        new SignRequestClaimsSet(CLIENT_ID, AUDIENCE, now, now.plusSeconds(300), signRequest);

    Assertions.assertEquals(CLIENT_ID, claims.getClientID());
    Assertions.assertEquals(List.of(AUDIENCE), claims.getAudience());
    Assertions.assertEquals(now.truncatedTo(ChronoUnit.SECONDS), claims.getIssueTime());
    Assertions.assertEquals(now.plusSeconds(300).truncatedTo(ChronoUnit.SECONDS), claims.getExpirationTime());
    Assertions.assertEquals(signRequest, claims.getSignRequest());
    Assertions.assertNotNull(claims.toString());
  }

  @Test
  public void testJWTClaimsSet() throws Exception {
    final Instant now = Instant.now();
    final SignRequest signRequest = new SignRequest("This is the text to sign".getBytes(), SIGN_MESSAGE);
    final SignRequestClaimsSet claims =
        new SignRequestClaimsSet(CLIENT_ID, AUDIENCE, now, now.plusSeconds(300), signRequest);

    final JWTClaimsSet jwtClaims = claims.toJWTClaimsSet();
    final Map<String, Object> json = jwtClaims.toJSONObject();

    Assertions.assertEquals(CLIENT_ID.getValue(), json.get("iss"));
    Assertions.assertEquals(AUDIENCE.getValue(), json.get("aud"));
    Assertions.assertEquals(now.getEpochSecond(), json.get("iat"));
    Assertions.assertEquals(now.getEpochSecond() + 300, json.get("exp"));
    Assertions.assertEquals(signRequest.getTbsData().toString(), json.get("tbs_data"));
    Assertions.assertTrue(json.get("sign_message") instanceof Map);

    final SignRequestClaimsSet claims2 = SignRequestClaimsSet.parse(jwtClaims);
    Assertions.assertEquals(claims, claims2);
    Assertions.assertEquals(claims.hashCode(), claims2.hashCode());
  }

  @Test
  public void testSignApprovalNoTimes() throws Exception {
    final SignRequestClaimsSet claims = new SignRequestClaimsSet(CLIENT_ID, AUDIENCE, null, null,
        new SignRequest(SIGN_MESSAGE));

    final JWTClaimsSet jwtClaims = claims.toJWTClaimsSet();
    Assertions.assertNull(jwtClaims.getIssueTime());
    Assertions.assertNull(jwtClaims.getExpirationTime());
    Assertions.assertNull(jwtClaims.getClaim("tbs_data"));

    final SignRequestClaimsSet claims2 = SignRequestClaimsSet.parse(jwtClaims);
    Assertions.assertEquals(claims, claims2);
    Assertions.assertNull(claims2.getIssueTime());
    Assertions.assertNull(claims2.getExpirationTime());
  }

  @Test
  public void testSignAndParse() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_256).keyID("client-sign-1").generate();
    final Instant now = Instant.now();
    final SignRequestClaimsSet claims = new SignRequestClaimsSet(CLIENT_ID, AUDIENCE, now, now.plusSeconds(300),
        new SignRequest("This is the text to sign".getBytes(), SIGN_MESSAGE));

    final String serialized = claims.sign(new ECDSASigner(key),
        new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build()).serialize();

    final SignedJWT jwt = SignedJWT.parse(serialized);
    Assertions.assertTrue(jwt.verify(new ECDSAVerifier(key.toPublicJWK())));
    Assertions.assertEquals(claims, SignRequestClaimsSet.parse(jwt.getJWTClaimsSet()));
  }

  @Test
  public void testMultipleAudience() throws Exception {
    final List<Audience> audience = List.of(AUDIENCE, new Audience("https://server.example.com/authorize"));
    final SignRequestClaimsSet claims = new SignRequestClaimsSet(CLIENT_ID, audience, null, null,
        new SignRequest(SIGN_MESSAGE));
    Assertions.assertEquals(audience, SignRequestClaimsSet.parse(claims.toJWTClaimsSet()).getAudience());
  }

  @Test
  public void testParseErrors() {
    final SignRequest signRequest = new SignRequest(SIGN_MESSAGE);

    final JWTClaimsSet noIss = new JWTClaimsSet.Builder()
        .audience(AUDIENCE.getValue())
        .claim("sign_message", SIGN_MESSAGE.toJSONObject())
        .build();
    Assertions.assertEquals("Missing required claim iss",
        Assertions.assertThrows(ParseException.class, () -> SignRequestClaimsSet.parse(noIss)).getMessage());

    final JWTClaimsSet noAud = new JWTClaimsSet.Builder()
        .issuer(CLIENT_ID.getValue())
        .claim("sign_message", signRequest.toJSONObject().get("sign_message"))
        .build();
    Assertions.assertEquals("Missing required claim aud",
        Assertions.assertThrows(ParseException.class, () -> SignRequestClaimsSet.parse(noAud)).getMessage());

    final JWTClaimsSet noSignMessage = new JWTClaimsSet.Builder()
        .issuer(CLIENT_ID.getValue())
        .audience(AUDIENCE.getValue())
        .build();
    Assertions.assertEquals("Missing required field sign_message",
        Assertions.assertThrows(ParseException.class, () -> SignRequestClaimsSet.parse(noSignMessage)).getMessage());
  }

  @Test
  public void testConstructorErrors() {
    final SignRequest signRequest = new SignRequest(SIGN_MESSAGE);
    Assertions.assertThrows(NullPointerException.class,
        () -> new SignRequestClaimsSet(null, AUDIENCE, null, null, signRequest));
    Assertions.assertThrows(NullPointerException.class,
        () -> new SignRequestClaimsSet(CLIENT_ID, (Audience) null, null, null, signRequest));
    Assertions.assertThrows(IllegalArgumentException.class,
        () -> new SignRequestClaimsSet(CLIENT_ID, List.of(), null, null, signRequest));
    Assertions.assertThrows(NullPointerException.class,
        () -> new SignRequestClaimsSet(CLIENT_ID, AUDIENCE, null, null, null));
  }

}
