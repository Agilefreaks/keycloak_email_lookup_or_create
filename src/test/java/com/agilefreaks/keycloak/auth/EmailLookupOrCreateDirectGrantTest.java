package com.agilefreaks.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

/** The same authenticator in a direct grant flow ({@code getFlowPath() == "token"}). */
class EmailLookupOrCreateDirectGrantTest {

  private static final String EMAIL = "visitor@example.com";

  private final EmailLookupOrCreateAuthenticator auth = new EmailLookupOrCreateAuthenticator();
  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private UserProvider users;
  private RealmModel realm;
  private AuthenticationSessionModel authSession;
  private EventBuilder event;
  private EventBuilder sideEvent;
  private MultivaluedMap<String, String> formData;

  @BeforeEach
  void setup() {
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    users = mock(UserProvider.class);
    realm = mock(RealmModel.class);
    authSession = mock(AuthenticationSessionModel.class);
    event = mock(EventBuilder.class, RETURNS_SELF);
    sideEvent = mock(EventBuilder.class, RETURNS_SELF);
    HttpRequest httpRequest = mock(HttpRequest.class);
    formData = new MultivaluedHashMap<>();

    when(ctx.getFlowPath()).thenReturn(EmailLookupOrCreateAuthenticator.FLOW_PATH_TOKEN);
    when(ctx.getSession()).thenReturn(session);
    when(session.users()).thenReturn(users);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getHttpRequest()).thenReturn(httpRequest);
    when(ctx.getAuthenticationSession()).thenReturn(authSession);
    when(ctx.getEvent()).thenReturn(event);
    when(event.clone()).thenReturn(sideEvent);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
  }

  private UserModel existingUser(boolean enabled) {
    UserModel user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(enabled);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(user);
    return user;
  }

  private Response captureFailure(AuthenticationFlowError expected) {
    ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
    verify(ctx).failure(eq(expected), captor.capture());
    return captor.getValue();
  }

  private static OAuth2ErrorRepresentation body(Response response) {
    return (OAuth2ErrorRepresentation) response.getEntity();
  }

  @Test
  void rejectsAMissingUsername() {
    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.INVALID_USER);
    assertEquals(400, response.getStatus());
    assertEquals(MediaType.APPLICATION_JSON_TYPE, response.getMediaType());
    assertEquals("invalid_request", body(response).getError());
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

    verify(ctx, never()).form();
    verify(ctx, never()).challenge(any());
  }

  @Test
  void findsAnExistingUserAndNormalisesTheAddress() {
    UserModel existing = existingUser(true);
    formData.putSingle("username", "  Visitor@Example.COM ");

    auth.authenticate(ctx);

    verify(ctx).setUser(existing);
    verify(ctx).success();
    verify(users, never()).addUser(any(), anyString());
  }

  @Test
  void acceptsTheEmailParameterAsAFallback() {
    UserModel existing = existingUser(true);
    formData.putSingle("email", EMAIL);

    auth.authenticate(ctx);

    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void createsAnEnabledUserForAnUnknownAddress() {
    UserModel created = mock(UserModel.class);
    when(created.isEnabled()).thenReturn(true);
    when(users.addUser(realm, EMAIL)).thenReturn(created);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    verify(created).setEmail(EMAIL);
    verify(created).setEnabled(true);
    verify(ctx).setUser(created);
    verify(ctx).success();
    // Direct grant rejects a user with a pending required action.
    verify(created, never()).addRequiredAction(anyString());
    verify(created, never()).addRequiredAction(any(UserModel.RequiredAction.class));
    verify(sideEvent).event(EventType.REGISTER);
  }

  @Test
  void recordsTheAttemptedUsername() {
    existingUser(true);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    verify(authSession).setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, EMAIL);
  }

  @Test
  void refusesADisabledUser() {
    existingUser(false);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.USER_DISABLED);
    assertEquals("invalid_grant", body(response).getError());
    verify(event).error(Errors.USER_DISABLED);
    verify(ctx, never()).success();
  }

  @Test
  void refusesAUserLockedOutByBruteForceProtection() {
    UserModel existing = existingUser(true);
    BruteForceProtector protector = mock(BruteForceProtector.class);
    when(realm.isBruteForceProtected()).thenReturn(true);
    when(ctx.getProtector()).thenReturn(protector);
    when(protector.isTemporarilyDisabled(session, realm, existing)).thenReturn(true);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    Response response = captureFailure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
    assertEquals("invalid_grant", body(response).getError());
    verify(ctx, never()).success();
  }

  @Test
  void aLostRaceCreatingTheUserUsesTheOneThatWon() {
    UserModel winner = mock(UserModel.class);
    when(winner.isEnabled()).thenReturn(true);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null).thenReturn(winner);
    when(users.addUser(realm, EMAIL)).thenThrow(new ModelDuplicateException("username exists"));
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    // Regression: the loser used to get an HTTP 500.
    verify(ctx).setUser(winner);
    verify(ctx).success();
    verify(event)
        .detail(
            EmailLookupOrCreateAuthenticator.DETAIL_USER_SOURCE,
            EmailLookupOrCreateAuthenticator.SOURCE_EXISTING);
    verify(sideEvent, never()).event(EventType.REGISTER);
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
    UserModel byUsername = mock(UserModel.class);
    when(byUsername.isEnabled()).thenReturn(true);
    when(users.getUserByUsername(realm, EMAIL)).thenReturn(byUsername);
    formData.putSingle("username", EMAIL);

    auth.authenticate(ctx);

    verify(byUsername).setEmail(EMAIL);
    verify(ctx).success();
  }

  @Test
  void normalisesTheAddressIndependentlyOfTheDefaultLocale() {
    UserModel existing = mock(UserModel.class);
    when(existing.isEnabled()).thenReturn(true);
    when(users.getUserByEmail(realm, "ivan@example.com")).thenReturn(existing);
    formData.putSingle("username", "IVAN@EXAMPLE.COM");

    auth.authenticate(ctx);

    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void anUpstreamStepThatAlreadyIdentifiedTheUserShortCircuits() {
    when(ctx.getUser()).thenReturn(mock(UserModel.class));

    auth.authenticate(ctx);

    verify(ctx).success();
    verify(users, never()).addUser(any(), anyString());
  }
}
