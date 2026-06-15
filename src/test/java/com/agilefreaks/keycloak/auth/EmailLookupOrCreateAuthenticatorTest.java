package com.agilefreaks.keycloak.auth;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

class EmailLookupOrCreateAuthenticatorTest {

  private EmailLookupOrCreateAuthenticator auth;
  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private UserProvider users;
  private RealmModel realm;
  private LoginFormsProvider form;
  private HttpRequest httpRequest;
  private AuthenticationSessionModel authSession;
  private MultivaluedMap<String, String> formData;

  @BeforeEach
  void setup() {
    auth = new EmailLookupOrCreateAuthenticator();
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    users = mock(UserProvider.class);
    realm = mock(RealmModel.class);
    form = mock(LoginFormsProvider.class);
    httpRequest = mock(HttpRequest.class);
    authSession = mock(AuthenticationSessionModel.class);
    formData = new MultivaluedHashMap<>();

    when(ctx.getSession()).thenReturn(session);
    when(session.users()).thenReturn(users);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
    when(ctx.getAuthenticationSession()).thenReturn(authSession);
    when(ctx.form()).thenReturn(form);
    when(form.setError(anyString())).thenReturn(form);
    when(form.createLoginUsername()).thenReturn(mock(Response.class));
  }

  @Test
  void authenticate_challengesWhenNoUser() {
    when(ctx.getUser()).thenReturn(null);

    auth.authenticate(ctx);

    verify(form).createLoginUsername();
    verify(ctx).challenge(any());
    verify(ctx, never()).success();
  }

  @Test
  void authenticate_successWhenUserAlreadyPresent() {
    when(ctx.getUser()).thenReturn(mock(UserModel.class));

    auth.authenticate(ctx);

    verify(ctx).success();
    verify(ctx, never()).challenge(any());
  }

  @Test
  void action_createsUserWhenUnknown_andNormalizesEmail() {
    formData.putSingle("username", "  New@Example.com  ");
    when(users.getUserByEmail(realm, "new@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "new@example.com")).thenReturn(null);
    UserModel created = mock(UserModel.class);
    when(users.addUser(realm, "new@example.com")).thenReturn(created);

    auth.action(ctx);

    verify(users).addUser(realm, "new@example.com");
    verify(created).setEnabled(true);
    verify(created).setEmail("new@example.com");
    verify(ctx).setUser(created);
    verify(ctx).success();
    verify(authSession)
        .setAuthNote(
            eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("new@example.com"));
  }

  @Test
  void action_usesExistingUser_noCreate() {
    formData.putSingle("username", "existing@example.com");
    UserModel existing = mock(UserModel.class);
    when(users.getUserByEmail(realm, "existing@example.com")).thenReturn(existing);

    auth.action(ctx);

    verify(users, never()).addUser(any(), anyString());
    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void action_fallsBackToUsernameLookup() {
    formData.putSingle("username", "byusername@example.com");
    when(users.getUserByEmail(realm, "byusername@example.com")).thenReturn(null);
    UserModel byUsername = mock(UserModel.class);
    when(users.getUserByUsername(realm, "byusername@example.com")).thenReturn(byUsername);

    auth.action(ctx);

    verify(users, never()).addUser(any(), anyString());
    verify(ctx).setUser(byUsername);
    verify(ctx).success();
  }

  @Test
  void action_rejectsInvalidEmail() {
    formData.putSingle("username", "not-an-email");

    auth.action(ctx);

    verify(form).setError(anyString());
    verify(ctx).challenge(any());
    verify(ctx, never()).success();
    verify(users, never()).addUser(any(), anyString());
  }

  @Test
  void action_rejectsMissingEmail() {
    auth.action(ctx); // no "username" in formData

    verify(ctx).challenge(any());
    verify(ctx, never()).success();
    verify(users, never()).addUser(any(), anyString());
  }

  @Test
  void requiresUser_isFalse() {
    org.junit.jupiter.api.Assertions.assertFalse(auth.requiresUser());
  }
}
