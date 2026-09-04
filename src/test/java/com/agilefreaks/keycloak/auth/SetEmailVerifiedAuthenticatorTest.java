package com.agilefreaks.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertTrue;
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
  private final AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
  private final UserModel user = mock(UserModel.class);

  @Test
  void verifiesWhenNotYetVerified() {
    when(ctx.getUser()).thenReturn(user);

    auth.authenticate(ctx);

    verify(user).setEmailVerified(true);
    verify(ctx).success();
  }

  @Test
  void skipsWhenAlreadyVerified() {
    when(ctx.getUser()).thenReturn(user);
    when(user.isEmailVerified()).thenReturn(true);

    auth.authenticate(ctx);

    verify(user, never()).setEmailVerified(anyBoolean());
    verify(ctx).success();
  }

  @Test
  void succeedsWithoutUser() {
    auth.authenticate(ctx);

    verify(ctx).success();
  }

  @Test
  void requiresUser_isTrue() {
    assertTrue(auth.requiresUser());
  }
}
