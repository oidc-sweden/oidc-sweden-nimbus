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
package se.oidc.nimbus.usermessage;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

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

    userMessage.addMessage(new UserMessage.Message("Detta är ett testmeddelande", "sv"));
    userMessage.addMessage(new UserMessage.Message("This is a test message", LangTag.parse("en")));
    userMessage.setMimeType(UserMessage.TEXT_MIME_TYPE);

    Assertions.assertTrue(userMessage.getMessages().size() == 2);
    Assertions.assertEquals("Detta är ett testmeddelande", userMessage.getMessage("sv"));
    Assertions.assertEquals("This is a test message", userMessage.getMessage("en"));
    Assertions.assertNull(userMessage.getDefaultMessage());
    Assertions.assertNull(userMessage.getMessage("de"));

    Assertions.assertEquals(UserMessage.TEXT_MIME_TYPE, userMessage.getMimeType());

    Assertions.assertNotNull(userMessage.toString());
    Assertions.assertTrue(userMessage.toString().startsWith("message"));
  }

  @Test
  public void test2() throws Exception {
    final UserMessage userMessage = new UserMessage(List.of(
        new UserMessage.Message("Detta är ett meddelande"),
        new UserMessage.Message("This is a message", "en")),
        UserMessage.TEXT_MIME_TYPE);

    final JSONObject json = userMessage.toJSONObject();
    System.out.println(json.toJSONString());

    System.out.println(userMessage);

    final UserMessage userMessage2 = UserMessage.parse(json);

    System.out.println(userMessage2);

    Assertions.assertEquals(userMessage, userMessage2);
    Assertions.assertEquals(userMessage.hashCode(), userMessage2.hashCode());
  }

  @Test
  public void testDuplicateMessages() {
    final UserMessage userMessage = new UserMessage();
    userMessage.addMessage(new UserMessage.Message("Default message"));
    userMessage.addMessage(new UserMessage.Message("English", "en"));

    Assertions.assertEquals("Default message parameter already exists",
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> userMessage.addMessage(new UserMessage.Message("Default message"))).getMessage());

    Assertions.assertEquals("Message with the same language tag already exists",
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> userMessage.addMessage(new UserMessage.Message("English", "en"))).getMessage());
  }

  @Test
  public void testGetBadLanguage() {
    final UserMessage userMessage = new UserMessage();
    userMessage.addMessage(new UserMessage.Message("Default message"));
    userMessage.addMessage(new UserMessage.Message("English", "en"));

    Assertions.assertNull(userMessage.getMessage("_ÖLOP"));
  }

  @Test
  public void testGetDefault() {
    final UserMessage userMessage = new UserMessage();

    Assertions.assertNull(userMessage.getDefaultMessage());

    userMessage.addMessage(new UserMessage.Message("Default message"));

    Assertions.assertEquals("Default message", userMessage.getDefaultMessage());
    Assertions.assertEquals("Default message", userMessage.getMessage((LangTag) null));
    Assertions.assertEquals("Default message", userMessage.getMessage((String) null));
  }

  @Test
  public void testParseErrors() {
    final JSONObject json1 = new JSONObject();
    json1.put("hello", "foo");

    Assertions.assertEquals("Missing message field(s)",
        Assertions.assertThrows(ParseException.class, () -> UserMessage.parse(json1)).getMessage());

    json1.put("message", 42);
    Assertions.assertEquals("Invalid user message object - Field message is expected to be a string",
        Assertions.assertThrows(ParseException.class, () -> UserMessage.parse(json1)).getMessage());
  }

}
