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
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Representation of the Client Provided User Message request parameter as defined in section 2.1 of
 * <a href="https://www.oidc.se/specifications/request-parameter-extensions.html">Authentication Request Parameter
 * Extensions for the Swedish OpenID Connect Profile</a>.
 *
 * @author Martin Lindström
 */
public class UserMessage {

  /** Symbolic constant for the {@code text/plain} MIME type. */
  public static final String TEXT_MIME_TYPE = "text/plain";

  /** Symbolic constant for the {@code text/markdown} MIME type. */
  public static final String MARKDOWN_MIME_TYPE = "text/markdown";

  /** Symbolic constant for the message parameter. */
  public static final String MESSAGE_PARAMETER_NAME = "message";

  /** A list messages. */
  private final List<Message> messages;

  /** The MIME type. */
  private String mimeType;

  /**
   * Default constructor.
   */
  public UserMessage() {
    this.messages = new ArrayList<>();
  }

  /**
   * Constructor.
   *
   * @param messages the message(s)
   * @param mimeType the MIME type (may be {@code null})
   */
  public UserMessage(final List<Message> messages, final String mimeType) {
    this();
    Objects.requireNonNull(messages, "messages must not be null");
    messages.forEach(this::addMessage);
    this.mimeType = mimeType;
  }

  /**
   * Adds a message.
   *
   * @param message the message
   */
  public void addMessage(final Message message) {
    if (message.getLanguage() == null) {
      if (this.messages.stream().anyMatch(m -> m.getLanguage() == null)) {
        throw new IllegalArgumentException("Default message parameter already exists");
      }
      this.messages.add(0, message);
    }
    else {
      if (this.messages.stream().anyMatch(m -> m.matches(message.getLanguage()))) {
        throw new IllegalArgumentException("Message with the same language tag already exists");
      }
      this.messages.add(message);
    }
  }

  /**
   * Gets a {@link List} of all messages.
   *
   * @return a {@link List} of all messages
   */
  public List<Message> getMessages() {
    return Collections.unmodifiableList(this.messages);
  }

  /**
   * Gets the "default" message, i.e., the message parameter with no language tag.
   *
   * @return the message or {@code null} if no message parameter without language tag exists
   */
  public String getDefaultMessage() {
    return this.messages.stream()
        .filter(m -> m.getLanguage() == null)
        .map(Message::getMessage)
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the message for the supplied language.
   *
   * @param langTag the language tag
   * @return the message, or {@code null} if not available
   */
  public String getMessage(final String langTag) {
    if (langTag == null) {
      return this.getDefaultMessage();
    }
    try {
      return this.getMessage(LangTag.parse(langTag));
    }
    catch (final LangTagException e) {
      return null;
    }
  }

  /**
   * Gets the message for the supplied language.
   *
   * @param langTag the language tag
   * @return the message, or {@code null} if not available
   */
  public String getMessage(final LangTag langTag) {
    if (langTag == null) {
      return this.getDefaultMessage();
    }
    return this.messages.stream()
        .filter(m -> m.matches(langTag))
        .map(Message::getMessage)
        .findFirst()
        .orElse(null);
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

    final String defaultMessage = this.getDefaultMessage();
    if (defaultMessage != null) {
      o.put(MESSAGE_PARAMETER_NAME, defaultMessage);
    }
    for (final Message msg : this.messages) {
      if (msg.getLanguage() == null) {
        continue;
      }
      o.put(MESSAGE_PARAMETER_NAME + "#" + msg.getLanguage().toString(), msg.getMessage());
    }
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

    final UserMessage userMessage = new UserMessage();

    try {
      final Object defaultMessage = jsonObject.get(MESSAGE_PARAMETER_NAME);
      if (defaultMessage != null) {
        if (!(defaultMessage instanceof String)) {
          throw new ParseException("Invalid user message object - Field message is expected to be a string");
        }
        userMessage.addMessage(Message.parse(MESSAGE_PARAMETER_NAME, (String) defaultMessage));
      }
      for (final Map.Entry<String, Object> entry : jsonObject.entrySet()) {
        if (entry.getKey().startsWith(MESSAGE_PARAMETER_NAME + "#")) {
          if (!(entry.getValue() instanceof String)) {
            throw new ParseException(
                "Invalid user message object - Field %s is expected to be a string".formatted(entry.getKey()));
          }
          userMessage.addMessage(Message.parse(entry.getKey(), (String) entry.getValue()));
        }
      }
      if (userMessage.getMessages().isEmpty()) {
        throw new ParseException("Missing %s field(s)".formatted(MESSAGE_PARAMETER_NAME));
      }
    }
    catch (final LangTagException | IllegalArgumentException e) {
      throw new ParseException(e.getMessage(), e);
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
    return Objects.hash(this.toString());
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
    return Objects.equals(this.toString(), other.toString());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder();
    for (final Message m : this.messages) {
      if (!sb.isEmpty()) {
        sb.append(", ");
      }
      if (m.getLanguage() == null) {
        sb.append(MESSAGE_PARAMETER_NAME);
      }
      else {
        sb.append(MESSAGE_PARAMETER_NAME).append('#').append(m.getLanguage().toString());
      }
      sb.append("=").append(m.getMessage());
    }
    sb.append(", mime_type=").append(this.mimeType != null ? this.mimeType : "not-set");
    return sb.toString();
  }

  /**
   * Representation of the message parameter.
   *
   * @author Martin Lindström
   */
  public static class Message {

    /** The message contents. */
    private final String message;

    /** The language tag (optional). */
    private final LangTag langTag;

    /**
     * Constructor setting up a message without a language tag.
     *
     * @param message the message
     */
    public Message(final String message) {
      this(message, (LangTag) null);
    }

    /**
     * Constructor.
     *
     * @param message the message contents
     * @param langTag the language tag
     */
    public Message(final String message, final LangTag langTag) {
      this.message = message;
      this.langTag = langTag;
    }

    /**
     * Constructor.
     *
     * @param message the message contents
     * @param langTag the language tag
     */
    public Message(final String message, final String langTag) {
      this.message = message;
      try {
        this.langTag = langTag != null ? LangTag.parse(langTag) : null;
      }
      catch (final LangTagException e) {
        throw new IllegalArgumentException("Invalid language tag", e);
      }
    }

    /**
     * Gets the message contents.
     *
     * @return the message contents
     */
    public String getMessage() {
      return this.message;
    }

    /**
     * Gets the language tag.
     *
     * @return the language tag or {@code null}
     */
    public LangTag getLanguage() {
      return this.langTag;
    }

    /**
     * Whether the supplied language tag matches the language tag of the message.
     *
     * @param langTag the language tag
     * @return {@code true} if there is a match and {@code false} otherwise
     */
    public boolean matches(final String langTag) {
      try {
        return this.langTag != null && this.matches(LangTag.parse(langTag));
      }
      catch (final LangTagException e) {
        return false;
      }
    }

    /**
     * Whether the supplied language tag matches the language tag of the message.
     *
     * @param langTag the language tag
     * @return {@code true} if there is a match and {@code false} otherwise
     */
    public boolean matches(final LangTag langTag) {
      if (this.langTag == null) {
        return false;
      }
      if (!Objects.equals(this.langTag.getPrimaryLanguage(), langTag.getPrimaryLanguage())) {
        return false;
      }
      if (this.langTag.getRegion() != null && langTag.getRegion() != null) {
        return Objects.equals(this.langTag.getRegion(), langTag.getRegion());
      }
      return true;
    }

    /**
     * Parses the parameter name ({@code message} or {@code message#tag}) and value into a {@link Message} object.
     *
     * @param parameterName the parameter name
     * @param message the message contents
     * @return a {@link Message} object
     * @throws LangTagException if there is an invalid language tag
     */
    public static Message parse(final String parameterName, final String message) throws LangTagException {
      if (MESSAGE_PARAMETER_NAME.equals(parameterName)) {
        return new Message(message);
      }

      if (!parameterName.startsWith(MESSAGE_PARAMETER_NAME + "#")) {
        return null;
      }
      final String langTag = parameterName.substring(MESSAGE_PARAMETER_NAME.length() + 1);
      return new Message(message, LangTag.parse(langTag));
    }

  }

}
