package com.agilefreaks.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserProvider;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.mockito.ArgumentCaptor;

/**
 * The same authenticator in a direct grant flow, where the address arrives as a form parameter of
 * the token request. It recognises that flow by {@code getFlowPath() == "token"}; the browser tests
 * leave it unset, which is why they exercise the form path unchanged.
 */
class EmailLookupOrCreateDirectGrantTest {

  private static final String EMAIL = "visitor@example.com";

  private EmailLookupOrCreateAuthenticator auth;
  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private UserProvider users;
  private RealmModel realm;
  private AuthenticationSessionModel authSession;
  private EventBuilder event;
  private MultivaluedMap<String, String> formData;

  @BeforeEach
  void setup() {
    auth = new EmailLookupOrCreateAuthenticator();
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    users = mock(UserProvider.class);
    realm = mock(RealmModel.class);
    authSession = mock(AuthenticationSessionModel.class);
    event = mock(EventBuilder.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    formData = new MultivaluedHashMap<>();

    when(ctx.getFlowPath()).thenReturn(EmailLookupOrCreateAuthenticator.FLOW_PATH_TOKEN);
    when(ctx.getSession()).thenReturn(session);
    when(session.users()).thenReturn(users);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getHttpRequest()).thenReturn(httpRequest);
    when(ctx.getAuthenticationSession()).thenReturn(authSession);
    when(ctx.getEvent()).thenReturn(event);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
  }

  private static UserModel enabledUser() {
    UserModel user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    return user;
  }

  private Response captureFailure(AuthenticationFlowError expected) {
    ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
    verify(ctx).failure(eq(expected), captor.capture());
    return captor.getValue();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> body(Response response) {
    try {
      return JsonSerialization.readValue(String.valueOf(response.getEntity()), Map.class);
    } catch (Exception e) {
      throw new AssertionError("response entity is not JSON: " + response.getEntity(), e);
    }
  }

  @Test
  void rejectsAMissingUsername() {
    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.INVALID_USER);
    assertEquals(400, response.getStatus());
    assertEquals("invalid_request", body(response).get("error"));
    verify(users, never()).addUser(any(), anyString());
    verify(ctx, never()).success();
  }

  @Test
  void rejectsSomethingThatIsNotAnEmailAddress() {
    formData.putSingle("username", "not-an-email");

    auth.authenticate(ctx);

    assertEquals(400, captureFailure(AuthenticationFlowError.INVALID_USER).getStatus());
    verify(users, never()).addUser(any(), anyString());
  }

  @Test
  void neverRendersAFormInADirectGrantFlow() {
    formData.putSingle("username", "not-an-email");

    auth.authenticate(ctx);

    // context.form() would blow up on a token request; the guard is that we never reach it.
    verify(ctx, never()).form();
    verify(ctx, never()).challenge(any());
  }

  @Test
  void findsAnExistingUserAndNormalisesTheAddress() {
    UserModel existing = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);
    formData.putSingle("username", "  Visitor@Example.COM ");

    auth.authenticate(ctx);

    verify(ctx).setUser(existing);
    verify(ctx).success();
    verify(users, never()).addUser(any(), anyString());
  }

  @Test
  void acceptsTheEmailParameterAsAFallback() {
    UserModel existing = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);
    formData.putSingle("email", EMAIL);

    auth.authenticate(ctx);

    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void createsAnEnabledUserForAnUnknownAddress() {
    UserModel created = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null);
    when(users.getUserByUsername(realm, EMAIL)).thenReturn(null);
    when(users.addUser(realm, EMAIL)).thenReturn(created);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    verify(created).setEmail(EMAIL);
    verify(created).setEnabled(true);
    verify(ctx).setUser(created);
    verify(ctx).success();
  }

  @Test
  void createdUserCarriesNoRequiredAction() {
    UserModel created = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null);
    when(users.addUser(realm, EMAIL)).thenReturn(created);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    // A direct grant rejects any user with a pending required action ("Account is not fully set
    // up"), so adding one here would break token login for every new account.
    verify(created, never()).addRequiredAction(anyString());
    verify(created, never()).addRequiredAction(any(UserModel.RequiredAction.class));
  }

  @Test
  void recordsTheAttemptedUsername() {
    UserModel existing = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    verify(authSession)
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, EMAIL);
  }

  @Test
  void refusesADisabledUser() {
    UserModel disabled = mock(UserModel.class);
    when(disabled.isEnabled()).thenReturn(false);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(disabled);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.USER_DISABLED);
    assertEquals("invalid_grant", body(response).get("error"));
    verify(ctx, never()).success();
  }

  @Test
  void refusesAUserLockedOutByBruteForceProtection() {
    UserModel existing = enabledUser();
    BruteForceProtector protector = mock(BruteForceProtector.class);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);
    when(realm.isBruteForceProtected()).thenReturn(true);
    when(ctx.getProtector()).thenReturn(protector);
    when(protector.isTemporarilyDisabled(session, realm, existing)).thenReturn(true);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
    assertEquals("invalid_grant", body(response).get("error"));
    verify(ctx, never()).success();
  }

  @Test
  void aLostRaceCreatingTheUserUsesTheOneThatWon() {
    UserModel winner = enabledUser();
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null).thenReturn(winner);
    when(users.addUser(realm, EMAIL)).thenThrow(new ModelDuplicateException("username exists"));
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    // Two requests for the same new address — a double-tapped submit, or a retried token
    // request — must not surface as a 500 to whichever one loses.
    verify(ctx).setUser(winner);
    verify(ctx).success();
  }

  @Test
  void refusesWhenSeveralUsersShareTheAddress() {
    when(users.getUserByEmail(realm, EMAIL))
        .thenThrow(new ModelDuplicateException("more than one user"));
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    assertEquals(400, captureFailure(AuthenticationFlowError.UNKNOWN_USER).getStatus());
    verify(ctx, never()).success();
    verify(event).error(Errors.INVALID_REGISTRATION);
  }

  @Test
  void fillsInAMissingEmailWhenMatchingOnUsername() {
    UserModel byUsername = enabledUser();
    when(byUsername.getEmail()).thenReturn(null);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null);
    when(users.getUserByUsername(realm, EMAIL)).thenReturn(byUsername);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    // Without an address the next step has nothing to verify against and the login dead-ends.
    verify(byUsername).setEmail(EMAIL);
    verify(ctx).success();
  }

  @Test
  void reportsAnEventErrorBeforeEachRefusal() {
    UserModel disabled = mock(UserModel.class);
    when(disabled.isEnabled()).thenReturn(false);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(disabled);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    // Without this the LOGIN_ERROR event carries no reason, so a lockout and a bad address look
    // identical in the event log.
    verify(event).error(Errors.USER_DISABLED);
  }

  @Test
  void normalisesTheAddressIndependentlyOfTheDefaultLocale() {
    UserModel existing = enabledUser();
    when(users.getUserByEmail(realm, "ivan@example.com")).thenReturn(existing);
    formData.putSingle("username", "IVAN@EXAMPLE.COM");

    auth.authenticate(ctx);

    // A Turkish default locale would lowercase I to a dotless i and miss this user.
    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void anUpstreamStepThatAlreadyIdentifiedTheUserShortCircuits() {
    UserModel alreadyKnown = enabledUser();
    when(ctx.getUser()).thenReturn(alreadyKnown);

    auth.authenticate(ctx);

    verify(ctx).success();
    verify(users, never()).addUser(any(), anyString());
  }
}
