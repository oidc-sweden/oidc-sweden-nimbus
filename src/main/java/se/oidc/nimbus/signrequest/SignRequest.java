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
package se.oidc.nimbus.signrequest;

import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;

import net.minidev.json.JSONObject;
import se.oidc.nimbus.usermessage.UserMessage;

/**
 * Representation of the Signature Request Parameter as defined in section 3.1 of
 * <a href="https://www.oidc.se/specifications/oidc-signature-extension.html"> Signature Extension for OpenID
 * Connect</a>.
 *
 * @author Martin Lindström
 */
public class SignRequest {

  /** The parameter name. */
  public static final String PARAMETER_NAME = "https://id.oidc.se/param/signRequest";

  /**
   * The data to be signed as a Base64-encoded string.
   */
  private final Base64 tbsData;

  /**
   * A sign message is the human readable text snippet that is displayed to the user as part of the signature process.
   * The sign_message field is a JSON object according to the https://id.oidc.se/param/userMessage request parameter as
   * defined in section 2.1 of
   * <a href="https://www.oidc.se/specifications/request-parameter-extensions.html">Authentication Request Parameter
   * Extensions for the Swedish OpenID Connect Profile</a>.
   */
  private final UserMessage signMessage;

  /**
   * Constructor.
   *
   * @param tbsData the to-be-signed data as a Base64-encoded string
   * @param signMessage the "sign message", i.e., the user message to display during the signature operation
   */
  public SignRequest(final Base64 tbsData, final UserMessage signMessage) {
    this.tbsData = Objects.requireNonNull(tbsData, "tbsData must not be null");
    this.signMessage = Objects.requireNonNull(signMessage, "signMessage must not be null");
  }

  /**
   * Constructor.
   *
   * @param tbsDataContents the raw to-be-signed data
   * @param signMessage the "sign message", i.e., the user message to display during the signature operation
   */
  public SignRequest(final byte[] tbsDataContents, final UserMessage signMessage) {
    this.tbsData = Base64.encode(Objects.requireNonNull(tbsDataContents, "tbsDataContents must not be null"));
    this.signMessage = Objects.requireNonNull(signMessage, "signMessage must not be null");
  }

  /**
   * Gets the data to be signed as a Base64-encoded string.
   *
   * @return the TBS-data
   */
  public Base64 getTbsData() {
    return this.tbsData;
  }

  /**
   * Gets the string contents of the TBS data.
   * 
   * @return the byte contents of the TBS data
   */
  public byte[] getTbsDataContents() {
    return this.tbsData.decode();
  }

  /**
   * Gets the sign message to be displayed for the user during the signature operation.
   *
   * @return a {@link UserMessage} object
   */
  public UserMessage getSignMessage() {
    return this.signMessage;
  }

  /**
   * Returns the {@link JSONObject} for the sign request type.
   *
   * @return a {@link JSONObject}
   */
  public JSONObject toJSONObject() {
    final JSONObject o = new JSONObject();
    o.put("tbs_data", this.tbsData.toString());
    o.put("sign_message", this.signMessage.toJSONObject());
    return o;
  }

  /**
   * Parses the supplied {@link JSONObject} into a {@link SignRequest} object.
   *
   * @param jsonObject the JSON
   * @return a {@link SignRequest} object
   * @throws ParseException for parsing errors
   */
  @SuppressWarnings("unchecked")
  public static SignRequest parse(final JSONObject jsonObject) throws ParseException {

    final String tbsData = jsonObject.getAsString("tbs_data");
    if (tbsData == null) {
      throw new ParseException("Missing required field tbs_data");
    }
    // Ensure that it is valid Base64 ...    
    try {
      java.util.Base64.getDecoder().decode(tbsData);
    }
    catch (final Exception e) {
      throw new ParseException("tbs_data does not contain a valid Base64 string", e);
    }
    
    final Object signMessageObject = jsonObject.get("sign_message");
    if (signMessageObject == null) {
      throw new ParseException("Missing required field sign_message");
    }
    final UserMessage userMessage;
    if (JSONObject.class.isInstance(signMessageObject)) {
      userMessage = UserMessage.parse((JSONObject) signMessageObject);
    }
    else if (Map.class.isInstance(signMessageObject)) {
      userMessage = UserMessage.parse(new JSONObject((Map<String, ?>) signMessageObject));
    }
    else {
      throw new ParseException("Invalid type for sign_message");
    }
    return new SignRequest(new Base64(tbsData), userMessage);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.signMessage, this.tbsData);
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
    final SignRequest other = (SignRequest) obj;
    return Objects.equals(this.signMessage, other.signMessage) && Objects.equals(this.tbsData, other.tbsData);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "tbs_data=" + this.tbsData.toJSONString() + ", sign_message=[" + this.signMessage + "]";
  }

}
