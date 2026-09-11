package com.agilefreaks.keycloak.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Marks the authenticated user's email as verified. Place it after the step that proves ownership
 * of the address, so reaching it is the proof.
 */
public class SetEmailVerifiedAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user != null && !user.isEmailVerified()) {
      user.setEmailVerified(true);
      // Only the transition is an event; reaching this step again on a later login is not.
      context
          .getEvent()
          .clone()
          .event(EventType.VERIFY_EMAIL)
          .user(user)
          .detail(Details.EMAIL, user.getEmail())
          .success();
    }
    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context) {}

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
