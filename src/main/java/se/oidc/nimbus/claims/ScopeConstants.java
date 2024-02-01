/*
 * Copyright 2023-2024 OIDC Sweden
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

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.oidc.nimbus.claims.OidcScopeValue.ClaimRequirement;

/**
 * Constants for the scopes defined in
 * <a href="https://www.oidc.se/specifications/swedish-oidc-claims-specification.html">Claims and Scopes
 * Specification for the Swedish OpenID Connect Profile</a>.
 *
 * @author Martin Lindström
 */
public class ScopeConstants {

  /**
   * A scope that defines a claim set that provides basic natural person information normally associated with a Swedish
   * eID.
   */
  public static final OidcScopeValue NATURAL_PERSON_INFO =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonInfo",
          new ClaimRequirement[] {
              ClaimRequirement.of(PersonClaims.FAMILY_NAME_CLAIM_NAME),
              ClaimRequirement.of(PersonClaims.GIVEN_NAME_CLAIM_NAME),
              ClaimRequirement.of(PersonClaims.MIDDLE_NAME_CLAIM_NAME),
              ClaimRequirement.of(PersonClaims.NAME_CLAIM_NAME),
              ClaimRequirement.of(PersonClaims.BIRTHDATE_CLAIM_NAME) });

  /**
   * A scope that requests a Swedish civic registration number (personnummer) or a Swedish coordination number
   * (samordningsnummer). These identity numbers are often used as primary identities at public Swedish organizations.
   */
  public static final OidcScopeValue NATURAL_PERSON_PERSONAL_NUMBER =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonNumber",
          new ClaimRequirement[] {
              ClaimRequirement.of(ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME, true, true, true),
              ClaimRequirement.of(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME, true, true, true) });

  /**
   * The “Natural Person Organizational Identity” scope requests basic organizational identity information claims about
   * a person. The organizational identity does not imply that the subject has any particular relationship with or
   * standing within the organization, but rather that this identity has been issued/provided by that organization for
   * any particular reason (employee, customer, consultant, etc.).
   */
  public static final OidcScopeValue NATURAL_PERSON_ORGANIZATIONAL_IDENTITY =
      new OidcScopeValue("https://id.oidc.se/scope/naturalPersonOrgId",
          new ClaimRequirement[] {
              ClaimRequirement.of(ClaimConstants.ORGANIZATIONAL_AFFILIATION_CLAIM_NAME, true, true, true),
              ClaimRequirement.of(PersonClaims.NAME_CLAIM_NAME, false, false, true),
              ClaimRequirement.of(ClaimConstants.ORGANIZATION_NAME_CLAIM_NAME, false, false, true),
              ClaimRequirement.of(ClaimConstants.ORGANIZATION_NUMBER_CLAIM_NAME, false, false, true) });

  /**
   * The scope has two purposes; it indicates for the OpenID Provider that the request in which the scope is included is
   * a "signature request" and requests claims.
   */
  public static final OidcScopeValue SIGN =
      new OidcScopeValue("https://id.oidc.se/scope/sign",
          new ClaimRequirement[] {
              ClaimRequirement.of(ClaimConstants.USER_SIGNATURE_CLAIM_NAME, true, true, false),
              ClaimRequirement.of(IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME, true, true, false)
          });

  // Hidden constructor.
  private ScopeConstants() {
  }

}
