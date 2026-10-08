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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.oidc.nimbus.claims.ParameterConstants;
import se.oidc.nimbus.usermessage.UserMessage;

import java.net.URI;
import java.time.Instant;
import java.util.List;

/**
 * Test cases for SignRequestParameterUtils.
 *
 * @author Martin Lindström
 */
public class SignRequestParameterUtilsTest {

  private static final ClientID CLIENT_ID = new ClientID("https://client.example.com");

  private static final SignRequest SIGN_REQUEST = new SignRequest("This is the text to sign".getBytes(),
      new UserMessage(List.of(new UserMessage.Message("Approve signature", "en")), UserMessage.TEXT_MIME_TYPE));

  @Test
  public void testGetSignRequestJWT() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_256).generate();
    final Instant now = Instant.now();
    final SignRequestClaimsSet claims = new SignRequestClaimsSet(CLIENT_ID, new Audience("https://server.example.com"),
        now, now.plusSeconds(300), SIGN_REQUEST);
    final String jwt = claims.sign(new ECDSASigner(key), new JWSHeader(JWSAlgorithm.ES256)).serialize();

    final JWT result = SignRequestParameterUtils.getSignRequestJWT(request(jwt));
    Assertions.assertInstanceOf(SignedJWT.class, result);
    Assertions.assertEquals(claims, SignRequestClaimsSet.parse(result.getJWTClaimsSet()));
  }

  @Test
  public void testGetSignRequestJWTMissing() throws Exception {
    Assertions.assertNull(SignRequestParameterUtils.getSignRequestJWT(request()));
  }

  @Test
  public void testGetSignRequestJWTErrors() {
    Assertions.assertThrows(ParseException.class,
        () -> SignRequestParameterUtils.getSignRequestJWT(request("not-a-jwt")));

    final String plain = new PlainJWT(new JWTClaimsSet.Builder().issuer(CLIENT_ID.getValue()).build()).serialize();
    Assertions.assertThrows(ParseException.class,
        () -> SignRequestParameterUtils.getSignRequestJWT(request(plain)));

    Assertions.assertThrows(ParseException.class,
        () -> SignRequestParameterUtils.getSignRequestJWT(request("a.b.c", "d.e.f")));
  }

  @Test
  public void testGetSignRequestFromRequestObject() throws Exception {
    final JWTClaimsSet requestObjectClaims = new JWTClaimsSet.Builder()
        .issuer(CLIENT_ID.getValue())
        .audience("https://server.example.com")
        .claim(ParameterConstants.SIGN_REQUEST_PARAM_NAME, SIGN_REQUEST.toJSONObject())
        .build();
    Assertions.assertEquals(SIGN_REQUEST, SignRequestParameterUtils.getSignRequest(requestObjectClaims));

    // After serialization and parsing, the claim is a plain Map
    final JWTClaimsSet parsed = JWTClaimsSet.parse(requestObjectClaims.toString());
    Assertions.assertEquals(SIGN_REQUEST, SignRequestParameterUtils.getSignRequest(parsed));
  }

  @Test
  public void testGetSignRequestFromRequestObjectMissingOrInvalid() throws Exception {
    Assertions.assertNull(SignRequestParameterUtils.getSignRequest(
        new JWTClaimsSet.Builder().issuer(CLIENT_ID.getValue()).build()));

    final JWTClaimsSet invalid = new JWTClaimsSet.Builder()
        .claim(ParameterConstants.SIGN_REQUEST_PARAM_NAME, "a.b.c")
        .build();
    Assertions.assertThrows(ParseException.class, () -> SignRequestParameterUtils.getSignRequest(invalid));
  }

  private static AuthenticationRequest request(final String... signRequestValues) {
    final AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
        ResponseType.CODE, new Scope("openid"), CLIENT_ID, URI.create("https://client.example.com/cb"))
        .endpointURI(URI.create("https://server.example.com/authorize"));
    if (signRequestValues.length > 0) {
      builder.customParameter(ParameterConstants.SIGN_REQUEST_PARAM_NAME, signRequestValues);
    }
    return builder.build();
  }

}
