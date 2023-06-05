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
package se.oidc.nimbus.claims;

/**
 * Representation of the claims defined within the OIDC Sweden specifications.
 * 
 * @author Martin Lindström
 */
public class ClaimConstants {

  /** Prefix for claims defined by OIDC Sweden. */
  public static final String OIDC_SWEDEN_CLAIMS_PREFIX = "https://id.oidc.se/claim/";

  /**
   * Swedish civic registration number (”personnummer”) according to
   * <a href="https://docs.swedenconnect.se/technical-framework/mirror/skv/skv704-8.pdf">SKV 704</a>.
   * <p>
   * <b>Type:</b> String where the format is 12 digits without hyphen.
   * </p>
   */
  public static final String PERSONAL_IDENTITY_NUMBER_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "personalIdentityNumber";

  /**
   * Swedish coordination number (”samordningsnummer”).
   * <p>
   * <b>Type:</b> String where the format is 12 digits without hyphen.
   * </p>
   */
  public static final String COORDINATION_NUMBER_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "coordinationNumber";

  /**
   * A Swedish coordination number is classified with a "level" that tells how well the holder has proven his or her
   * identity in conjunction with the issuance of the number. Possible levels are:
   * <ul>
   * <li>{@code confirmed} - The identity of the holder is fully confirmed.</li>
   * <li>{@code probable} - The identity of the holder is probable, but not fully confirmed.</li>
   * <li>{@code uncertain} - The identity of the holder is uncertain.</li>
   * </ul>
   * <p>
   * The {@code coordinationNumberLevel} claim may be used to represent this level when a coordination number is released.
   * </p>
   * <p>
   * <b>Type:</b> String holding any of the three values listed above.
   * </p>
   */
  public static final String COORDINATION_NUMBER_LEVEL_CLAIM_NAME =
      OIDC_SWEDEN_CLAIMS_PREFIX + "coordinationNumberLevel";
  
  /**
   * All individuals born in Sweden or moving to Sweden with the intention of staying one year or longer will be
   * assigned a personal identity number ("personnummer") and registered in the population register. Prior to being
   * assigned a Swedish personal identity number ("personnummer"), a coordination number (see
   * {@link #COORDINATION_NUMBER_CLAIM_NAME}) may be issued in order to enable communication with various government
   * authorities, healthcare institutions, higher education and banks.
   * <p>
   * In most cases regarding people that move to Sweden, a person first holds a coordination number during a period
   * before he or she is assigned a personal identity number. A typical use case is a person that seeks asylum and later
   * is given a residence permit. In this case the person may first hold a coordination number and if a residence permit
   * is given a personal identity number will be assigned.
   * </p>
   * <p>
   * Therefore, the OIDC Sweden profiles define the {@code previousCoordinationNumber} claim to enable matching a
   * previously held identity number to a newly assigned identity number. The {@code previousCoordinationNumber} claim
   * is typically released together with the "new" {@code personalIdentityNumber} claim in order to facilitate account
   * matching at a service provider.
   * </p>
   * <p>
   * <b>Type:</b> See {@link #COORDINATION_NUMBER_CLAIM_NAME}.
   * </p>
   */
  public static final String PREVIOUS_COORDINATION_NUMBER_CLAIM_NAME =
      OIDC_SWEDEN_CLAIMS_PREFIX + "previousCoordinationNumber";

  /**
   * Swedish organizational number ("organisationsnummer") according to
   * <a href="https://docs.swedenconnect.se/technical-framework/mirror/skv/skv709-8.pdf">SKV709</a>.
   * <p>
   * <b>Type:</b> String where the format is 10 digits without hyphen.
   * </p>
   */
  public static final String ORGANIZATION_NUMBER_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "orgNumber";

  /**
   * The personal identity at a Swedish organization (identified as a Swedish organizational number according to
   * {@link #ORGANIZATION_NUMBER_CLAIM_NAME}). The {@code orgAffiliation} claim is intended to be used as a primary
   * identity claim for global personal organizational identities. It consists of a personal identifier and an
   * organizational identifier code ({@code orgNumber}).
   * <p>
   * <b>Type:</b> String on the format {@code personal-id@org-number} where the {@code personal-id} part determined by
   * the organization and the {@code org-number} part is according to {@link #ORGANIZATION_NUMBER_CLAIM_NAME} above.
   * </p>
   */
  public static final String ORGANIZATIONAL_AFFILIATION_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "orgAffiliation";

  /**
   * Registered organization name.
   * <p>
   * <b>Type:</b> String
   * </p>
   */
  public static final String ORGANIZATION_NAME_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "orgName";

  /**
   * Organizational unit name.
   * <p>
   * <b>Type:</b> String
   * </p>
   */
  public static final String ORGANIZATIONAL_UNIT_NAME_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "orgUnit";

  /**
   * An X.509 certificate presented by the subject (user) during the authentication process.
   * <p>
   * <b>Type:</b> String. Base64-encoding of the DER-encoded certificate.
   * </p>
   */
  public static final String USER_CERTIFICATE_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "userCertificate";

  /**
   * A signature that was produced by the subject (user) during the authentication, or signature, process.
   * <p>
   * <b>Type:</b> String. Base64-encoding of the signature bytes.
   * </p>
   */
  public static final String USER_SIGNATURE_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "userSignature";

  /**
   * The start time of the user credential's validity.
   * <p>
   * <b>Type:</b> Integer. Seconds since epoch (1970-01-01).
   * </p>
   */
  public static final String CREDENTIALS_VALID_FROM_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "credentialValidFrom";

  /**
   * The end time of the user credential's validity.
   * <p>
   * <b>Type:</b> Integer. Seconds since epoch (1970-01-01).
   * </p>
   */
  public static final String CREDENTIALS_VALID_TO_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "credentialValidTo";

  /**
   * If the user authenticated using an online device holding the user credentials (such as a mobile phone) this claim
   * may be used to inform the relying party of the IP address of that device.
   * <p>
   * <b>Type:</b> An IPv4 or IPv6 address in String format.
   * </p>
   */
  public static final String DEVICE_IP_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "deviceIp";

  /**
   * A generic claim that can be issued by an OpenID Provider to supply the client with proof, or evidence, about the
   * authentication process. It may be especially interesting for some clients if the provider has delegated all, or
   * parts, of the authentication process to another party. In such cases, the claim can hold the encoding of an OCSP
   * response, a SAML assertion, or even a signed JWT.
   * <p>
   * <b>Type:</b> String. Base64-format.
   * </p>
   */
  public static final String AUTHENTICATION_EVIDENCE_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "authnEvidence";

  /**
   * A claim representing the identity of an "authentication provider". This claim is intended to be released by OpenID
   * Providers that offers several authentication mechanisms (providers). This includes OpenID Providers that delegate,
   * or proxy, the user authentication to other services.
   * <p>
   * By including this claim in an ID token the OP informs the Relying Party about the identity of the provider
   * (mechanism or authority) that authenticated the user.
   * </p>
   * <p>
   * <b>Type:</b> String. Preferably an URI.
   * </p>
   */
  public static final String AUTHENTICATION_PROVIDER_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "authnProvider";

  /**
   * OpenID Core defines the address claim containing a country field, but there are many other areas where a country
   * needs to be represented other than in the context of an individual's address. The
   * {@code https://id.oidc.se/claim/country} claim is a general purpose claim that can be used to represent a country.
   * <p>
   * <b>Type:</b> String. ISO 3166-1 alpha-2 two letter country code.
   * </p>
   */
  public static final String COUNTRY_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "country";

  /**
   * Claims that corresponds to the {@code name} claim defined in OpenID Core but is the full name at the time of birth
   * for the subject.
   * <p>
   * <b>Type:</b> String.
   * </p>
   */
  public static final String BIRTH_NAME_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "birthName";

  /**
   * Claim representing the place of birth for the subject. The OIDC Sweden specifications does not define "place".
   * Depending on the context it may be "City" or "City, Country" or any other representation.
   * <p>
   * <b>Type:</b> String.
   * </p>
   */
  public static final String PLACE_OF_BIRTH_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "placeOfbirth";
  
  /**
   * Claim representing the age (in years) of the subject person.
   * <p>
   * <b>Type:</b> Integer.
   * </p>
   */
  public static final String AGE_CLAIM_NAME = OIDC_SWEDEN_CLAIMS_PREFIX + "age";

}
