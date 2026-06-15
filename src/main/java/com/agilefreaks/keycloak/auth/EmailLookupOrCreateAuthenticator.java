package com.agilefreaks.keycloak.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

/**
 * Passwordless login-or-signup: renders the email form, then looks up the user
 * by email and creates one if none exists, setting it on the flow so the
 * following step can verify ownership (e.g. an email/SMS one-time code or a
 * magic link). The optional {@code set-email-verified} authenticator can mark
 * the email verified once that step succeeds.
 */
public class EmailLookupOrCreateAuthenticator implements Authenticator {

  static final String FIELD = "username";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // A cookie (or upstream step) may already have identified the user.
    if (context.getUser() != null) {
      context.success();
      return;
    }
    // createLoginUsername() renders login-username.ftl with the standard form
    // beans (login, social, etc.) populated — the same call the built-in
    // username form uses. (Plain createForm("login-username.ftl") leaves the
    // `login` bean null and the template errors.)
    context.challenge(context.form().createLoginUsername());
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String email = formData.getFirst(FIELD);

    if (email == null || email.trim().isEmpty() || !Validation.isEmailValid(email.trim())) {
      Response challenge = context.form()
          .setError(Messages.INVALID_EMAIL)
          .createLoginUsername();
      context.challenge(challenge);
      return;
    }

    email = email.trim().toLowerCase();
    // Record the attempted username (used by downstream form headers and login events).
    context.getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);

    KeycloakSession session = context.getSession();
    RealmModel realm = context.getRealm();

    UserModel user = session.users().getUserByEmail(realm, email);
    if (user == null) {
      user = session.users().getUserByUsername(realm, email);
    }
    if (user == null) {
      // New, unverified user; username = email. The next step verifies
      // ownership; emailVerified is flipped to true after that.
      user = session.users().addUser(realm, email);
      user.setEnabled(true);
      user.setEmail(email);
    }

    context.setUser(user);
    context.success();
  }

  @Override
  public boolean requiresUser() {
    return false;
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
