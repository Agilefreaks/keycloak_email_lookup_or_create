package com.agilefreaks.keycloak.auth;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;

class SetEmailVerifiedAuthenticatorTest {

  private final SetEmailVerifiedAuthenticator auth = new SetEmailVerifiedAuthenticator();

  @Test
  void verifiesWhenNotYetVerified() {
    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    UserModel user = mock(UserModel.class);
    when(ctx.getUser()).thenReturn(user);
    when(user.isEmailVerified()).thenReturn(false);

    auth.authenticate(ctx);

    verify(user).setEmailVerified(true);
    verify(ctx).success();
  }

  @Test
  void skipsWhenAlreadyVerified() {
    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    UserModel user = mock(UserModel.class);
    when(ctx.getUser()).thenReturn(user);
    when(user.isEmailVerified()).thenReturn(true);

    auth.authenticate(ctx);

    verify(user, never()).setEmailVerified(anyBoolean());
    verify(ctx).success();
  }

  @Test
  void succeedsWithoutUser() {
    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    when(ctx.getUser()).thenReturn(null);

    auth.authenticate(ctx);

    verify(ctx).success();
  }

  @Test
  void requiresUser_isTrue() {
    org.junit.jupiter.api.Assertions.assertTrue(auth.requiresUser());
  }
}
