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
package se.oidc.nimbus.usermessage;

import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.ParseException;

import net.minidev.json.JSONObject;

/**
 * Test cases for UserMessage.
 * 
 * @author Martin Lindström
 */
public class UserMessageTest {

  @Test
  public void test1() throws Exception {
    final UserMessage userMessage = new UserMessage();
    Assertions.assertTrue(userMessage.getMessages().isEmpty());
    Assertions.assertNull(userMessage.getMimeType());

    final JSONObject json = userMessage.toJSONObject();
    Assertions.assertEquals(userMessage, UserMessage.parse(json));

    userMessage.addMessage("sv", "Detta är ett testmeddelande");
    userMessage.addMessage("en", "This is a test message");
    userMessage.setMimeType(UserMessage.TEXT_MIME_TYPE);

    Assertions.assertTrue(userMessage.getMessages().size() == 2);
    Assertions.assertEquals("Detta är ett testmeddelande", userMessage.getMessage("sv"));
    Assertions.assertEquals("This is a test message", userMessage.getMessage("en"));
    Assertions.assertNull(userMessage.getMessage("de"));

    Assertions.assertEquals(UserMessage.TEXT_MIME_TYPE, userMessage.getMimeType());

    Assertions.assertNotNull(userMessage.toString());
    Assertions.assertTrue(userMessage.toString().startsWith("message="));
  }

  @Test
  public void test2() throws Exception {
    final UserMessage userMessage = new UserMessage(Map.of(
        "en", "This is a message",
        "sv", "Detta är ett meddelande"),
        UserMessage.TEXT_MIME_TYPE);

    final JSONObject json = userMessage.toJSONObject();
    System.out.println(json.toJSONString());

    final UserMessage userMessage2 = UserMessage.parse(json);
    Assertions.assertEquals(userMessage, userMessage2);
    Assertions.assertEquals(userMessage.hashCode(), userMessage2.hashCode());
  }

  @Test
  public void testBadLanguage() throws Exception {
    Assertions.assertEquals("Invalid language tag - english",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          new UserMessage(Map.of("english", "This is a message"), null);
        }).getMessage());

    final UserMessage um1 = new UserMessage();
    Assertions.assertEquals("Invalid language tag - english",
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
          um1.addMessage("english", "This is a message");
        }).getMessage());
  }
  
  @Test
  public void testParseErrors() throws Exception {
    final JSONObject json1 = new JSONObject();
    json1.put("hello", "foo");
    
    Assertions.assertEquals("Invalid user message object - Missing message field",
        Assertions.assertThrows(ParseException.class, () -> {
          UserMessage.parse(json1);
        }).getMessage());
    
    json1.put("message", "a string");
    Assertions.assertEquals("Invalid user message object - Field message is expected to be a map",
        Assertions.assertThrows(ParseException.class, () -> {
          UserMessage.parse(json1);
        }).getMessage());
    
    final JSONObject json2 = new JSONObject();
    json2.put("message", Map.of("english", "msg"));
    Assertions.assertEquals("Invalid user message object - unrecognized language tag",
        Assertions.assertThrows(ParseException.class, () -> {
          UserMessage.parse(json2);
        }).getMessage());
  }
  
  @Test
  public void testEqualsJustToGet100PercentJacocoCoverage() {
    UserMessage um1 = new UserMessage(Map.of("sv", "Svenska"), UserMessage.TEXT_MIME_TYPE);
    UserMessage um2 = new UserMessage(Map.of("en", "English"), UserMessage.TEXT_MIME_TYPE);
    Assertions.assertFalse(um1.equals(null));
    Assertions.assertFalse(um1.equals(um2));
    Assertions.assertFalse(um1.equals("other-type"));
    
    UserMessage um3 = new UserMessage(Map.of("sv", "Svenska"), UserMessage.MARKDOWN_MIME_TYPE);
    Assertions.assertFalse(um1.equals(um3));
    
    Assertions.assertTrue(um1.equals(um1));
  }
  
}
