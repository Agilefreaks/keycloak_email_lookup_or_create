package com.agilefreaks.keycloak.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Marks the authenticated user's email as verified. Intended as the final step
 * of a passwordless flow: it runs only after the preceding step has verified
 * ownership of the email, so reaching it is the proof.
 */
public class SetEmailVerifiedAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user != null && !user.isEmailVerified()) {
      user.setEmailVerified(true);
    }
    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // no form interaction
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // no-op
  }

  @Override
  public void close() {
    // no-op
  }
}
