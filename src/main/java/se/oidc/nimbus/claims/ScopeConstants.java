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

import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

/**
 * Constants for the scopes defined in
 * <a href="https://www.oidc.se/specifications/swedish-oidc-attribute-specification.html"> Attribute Specification for
 * the Swedish OpenID Connect Profile</a>.
 * 
 * @author Martin Lindström
 */
public class ScopeConstants {

  /**
   * A scope that defines a claim set that provides basic natural person information without revealing the civic
   * registration number of the subject.
   */
  public static final OidcScopeValue NATURAL_PERSON_NAME_INFORMATION =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonName",
          new String[] { 
              PersonClaims.FAMILY_NAME_CLAIM_NAME,
              PersonClaims.GIVEN_NAME_CLAIM_NAME,
              PersonClaims.NAME_CLAIM_NAME });

  /**
   * The scope extends the https://id.oidc.se/scope/naturalPersonName scope with a Swedish civic registration number
   * (personnummer) or a Swedish coordination number (samordningsnummer).
   */
  public static final OidcScopeValue NATURAL_PERSON_PERSONAL_NUMBER =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonNumber",
          new String[] {
              ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME,
              ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME,
              PersonClaims.FAMILY_NAME_CLAIM_NAME,
              PersonClaims.GIVEN_NAME_CLAIM_NAME,
              PersonClaims.NAME_CLAIM_NAME,
              PersonClaims.BIRTHDATE_CLAIM_NAME });

  /**
   * The “Natural Person Organizational Identity” scope provides basic organizational identity information about a
   * person. The organizational identity does not necessarily imply that the subject has any particular relationship
   * with or standing within the organization, but rather that this identity has been issued/provided by that
   * organization for any particular reason (employee, customer, consultant, etc.).
   */
  public static final OidcScopeValue NATURAL_PERSON_ORGANIZATIONAL_IDENTITY =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonOrgId",
          new String[] {
              PersonClaims.NAME_CLAIM_NAME,
              ClaimConstants.ORGANIZATIONAL_AFFILIATION_CLAIM_NAME,
              ClaimConstants.ORGANIZATION_NAME_CLAIM_NAME,
              ClaimConstants.ORGANIZATION_NUMBER_CLAIM_NAME });

  /**
   * A scope that is used to request claims that represents information from the authentication process and information
   * about the subject's credentials used to authenticate.
   * <p>
   * This specification declares all claims as optional except for the auth_time claim. A profile specification
   * extending this attribute specification MAY change requirements to Mandatory and declare additional claims.
   * </p>
   */
  public static final OidcScopeValue AUTHENTICATION_INFORMATION =
      new OidcScopeValue("https://id.oidc.se/scope/authnInfo",
          new String[] {
              "auth_time",
              "txn",
              ClaimConstants.USER_CERTIFICATE_CLAIM_NAME,
              ClaimConstants.CREDENTIALS_VALID_FROM_CLAIM_NAME,
              ClaimConstants.CREDENTIALS_VALID_TO_CLAIM_NAME,
              ClaimConstants.DEVICE_IP_CLAIM_NAME });

  // Hidden constructor.
  private ScopeConstants() {
  }

}
