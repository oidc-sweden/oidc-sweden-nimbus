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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;

import net.minidev.json.JSONObject;

/**
 * Representation of the Client Provided User Message request parameter as defined in section 2.1 of
 * <a href="https://www.oidc.se/specifications/request-parameter-extensions.html">Authentication Request Parameter
 * Extensions for the Swedish OpenID Connect Profile</a>.
 *
 * @author Martin Lindström
 */
public class UserMessage {

  /** The parameter name. */
  public static final String PARAMETER_NAME = "https://id.oidc.se/param/userMessage";

  /** Symbolic constant for the {@code text/plain} MIME type. */
  public static final String TEXT_MIME_TYPE = "text/plain";

  /** Symbolic constant for the {@code text/markdown} MIME type. */
  public static final String MARKDOWN_MIME_TYPE = "text/markdown";

  /** A map of language tags and messages. */
  private final Map<String, String> messages = new HashMap<>();

  /** The MIME type. */
  private String mimeType;

  /**
   * Default constructor.
   */
  public UserMessage() {
  }

  /**
   * Constructor.
   *
   * @param messages the message(s)
   * @param mimeType the MIME type (may be {@code null})
   */
  public UserMessage(final Map<String, String> messages, final String mimeType) {
    Objects.requireNonNull(messages, "messages must not be null");
    for (final Map.Entry<String, String> entry : messages.entrySet()) {
      try {
        LangTag.parse(entry.getKey());
      }
      catch (final LangTagException e) {
        throw new IllegalArgumentException("Invalid language tag - " + entry.getKey(), e);
      }
      this.messages.put(entry.getKey(), entry.getValue());
    }
    this.mimeType = mimeType;
  }

  /**
   * Adds a message.
   *
   * @param langTag the language tag
   * @param message the message
   */
  public void addMessage(final String langTag, final String message) {
    try {
      LangTag.parse(Objects.requireNonNull(langTag, "langTag must not be null"));
      this.messages.put(langTag, Objects.requireNonNull(message, "message must not be null"));
    }
    catch (final LangTagException e) {
      throw new IllegalArgumentException("Invalid language tag - " + langTag, e);
    }
  }

  /**
   * Gets a {@link Map} of all messages.
   *
   * @return a {@link Map} of all messages
   */
  public Map<String, String> getMessages() {
    return Collections.unmodifiableMap(this.messages);
  }

  /**
   * Gets the message for the supplied language.
   *
   * @param langTag the language tag
   * @return the message, or {@code null} if not available
   */
  public String getMessage(final String langTag) {
    return this.messages.get(langTag);
  }

  /**
   * Gets the MIME type.
   *
   * @return the MIME type, or {@code null} if it has not been assigned
   */
  public String getMimeType() {
    return this.mimeType;
  }

  /**
   * Assigns the MIME type.
   *
   * @param mimeType the MIME type
   */
  public void setMimeType(final String mimeType) {
    this.mimeType = mimeType;
  }

  /**
   * Returns the {@link JSONObject} for the user message type.
   *
   * @return a {@link JSONObject}
   */
  public JSONObject toJSONObject() {
    final JSONObject o = new JSONObject();
    o.put("message", this.messages);
    if (this.mimeType != null) {
      o.put("mime_type", this.mimeType);
    }
    return o;
  }

  /**
   * Parses the supplied {@link JSONObject} into a {@link UserMessage} object.
   *
   * @param jsonObject the JSON
   * @return a {@link UserMessage} object
   * @throws ParseException for parsing errors
   */
  public static UserMessage parse(final JSONObject jsonObject) throws ParseException {

    final Object messageObject = jsonObject.get("message");
    if (messageObject == null) {
      throw new ParseException("Invalid user message object - Missing message field");
    }
    if (!Map.class.isInstance(messageObject)) {
      throw new ParseException("Invalid user message object - Field message is expected to be a map");
    }
    final UserMessage userMessage = new UserMessage();
    for (final var entry : Map.class.cast(messageObject).entrySet()) {
      @SuppressWarnings("unchecked")
      final Map.Entry<String, String> e = (Map.Entry<String, String>) entry;
      try {
        LangTag.parse(e.getKey());
        userMessage.addMessage(e.getKey(), e.getValue());
      }
      catch (final LangTagException te) {
        throw new ParseException("Invalid user message object - unrecognized language tag", te);
      }
    }
    final String mimeType = jsonObject.getAsString("mime_type");
    if (mimeType != null) {
      userMessage.setMimeType(mimeType);
    }

    return userMessage;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.messages, this.mimeType);
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
    final UserMessage other = (UserMessage) obj;
    return Objects.equals(this.messages, other.messages) && Objects.equals(this.mimeType, other.mimeType);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "message=" + this.messages + ", mime_type=" + this.mimeType;
  }

}
