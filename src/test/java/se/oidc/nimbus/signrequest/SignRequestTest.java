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
package se.oidc.nimbus.signrequest;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.oidc.nimbus.usermessage.UserMessage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test cases for SignRequest.
 *
 * @author Martin Lindström
 */
public class SignRequestTest {

  @Test
  public void testCreateAndGet() {

    final UserMessage um = new UserMessage(List.of(
        new UserMessage.Message("Godkänn underskrift", "sv"),
        new UserMessage.Message("Approve signature", "en")),
        UserMessage.TEXT_MIME_TYPE);
    final SignRequest signRequest = new SignRequest(Base64.encode("This is the text to sign"), um);

    Assertions.assertEquals("This is the text to sign", signRequest.getTbsData().decodeToString());
    Assertions.assertArrayEquals("This is the text to sign".getBytes(), signRequest.getTbsDataContents());
    Assertions.assertEquals(um, signRequest.getSignMessage());

    Assertions.assertEquals(String.format("tbs_data=%s, sign_message=[%s]",
            signRequest.getTbsData().toJSONString(), um),
        signRequest.toString());
  }

  @Test
  public void testJsonAndParse() throws Exception {

    final UserMessage um =
        new UserMessage(List.of(
            new UserMessage.Message("Godkänn underskrift", "sv"),
            new UserMessage.Message("Approve signature", "en")),
            UserMessage.TEXT_MIME_TYPE);
    final SignRequest signRequest = new SignRequest("This is the text to sign".getBytes(), um);

    final JSONObject json = signRequest.toJSONObject();

    final SignRequest signRequest2 = SignRequest.parse(json);
    Assertions.assertEquals(signRequest, signRequest2);
    Assertions.assertEquals(signRequest.hashCode(), signRequest2.hashCode());
  }

  @Test
  public void testParseErrors() {
    final JSONObject json = new JSONObject();
    json.put("hello", "foo");

    Assertions.assertEquals("Missing required field tbs_data",
        Assertions.assertThrows(ParseException.class, () -> SignRequest.parse(json)).getMessage());

    json.put("tbs_data", "This is not base64");
    Assertions.assertEquals("tbs_data does not contain a valid Base64 string",
        Assertions.assertThrows(ParseException.class, () -> SignRequest.parse(json)).getMessage());

    json.put("tbs_data", Base64.encode("TBS").toString());
    Assertions.assertEquals("Missing required field sign_message",
        Assertions.assertThrows(ParseException.class, () -> SignRequest.parse(json)).getMessage());

    final UserMessage um = new UserMessage(List.of(
        new UserMessage.Message("Godkänn underskrift", "sv"),
        new UserMessage.Message("Approve signature", "en")),
        UserMessage.TEXT_MIME_TYPE);
    final JSONObject o = um.toJSONObject();
    final Map<String, Object> map = new HashMap<>();
    map.put("message#sv", o.get("message#sv"));
    map.put("message#en", o.get("message#en"));
    map.put("mime_type", o.get("mime_type"));

    json.put("sign_message", map);
    Assertions.assertDoesNotThrow(() -> {
      SignRequest.parse(json);
    });

    json.put("sign_message", "text");
    Assertions.assertEquals("Invalid type for sign_message",
        Assertions.assertThrows(ParseException.class, () -> SignRequest.parse(json)).getMessage());
  }

}
