package com.agilefreaks.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
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
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

class EmailLookupOrCreateAuthenticatorTest {

  private static final String EMAIL = "real@example.com";

  private EmailLookupOrCreateAuthenticator auth;
  private AuthenticationFlowContext ctx;
  private UserProvider users;
  private RealmModel realm;
  private LoginFormsProvider form;
  private AuthenticationSessionModel authSession;
  private MultivaluedMap<String, String> formData;
  private EventBuilder event;
  private EventBuilder sideEvent;

  @BeforeEach
  void setup() {
    auth = new EmailLookupOrCreateAuthenticator();
    ctx = mock(AuthenticationFlowContext.class);
    KeycloakSession session = mock(KeycloakSession.class);
    users = mock(UserProvider.class);
    realm = mock(RealmModel.class);
    form = mock(LoginFormsProvider.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    authSession = mock(AuthenticationSessionModel.class);
    formData = new MultivaluedHashMap<>();
    event = mock(EventBuilder.class, RETURNS_SELF);
    sideEvent = mock(EventBuilder.class, RETURNS_SELF);

    when(ctx.getEvent()).thenReturn(event);
    when(event.clone()).thenReturn(sideEvent);
    when(ctx.getSession()).thenReturn(session);
    when(session.users()).thenReturn(users);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
    when(ctx.getAuthenticationSession()).thenReturn(authSession);
    when(ctx.form()).thenReturn(form);
    when(form.createLoginUsername()).thenReturn(mock(Response.class));
  }

  @Test
  void authenticate_challengesWhenNoUser() {
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
    UserModel created = unknownAddress("new@example.com");

    auth.action(ctx);

    verify(created).setEnabled(true);
    verify(created).setEmail("new@example.com");
    verify(ctx).setUser(created);
    verify(ctx).success();
    verify(authSession)
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, "new@example.com");
  }

  @Test
  void action_usesExistingUser_noCreate() {
    formData.putSingle("username", EMAIL);
    UserModel existing = mock(UserModel.class);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);

    auth.action(ctx);

    verify(users, never()).addUser(any(), anyString());
    verify(ctx).setUser(existing);
    verify(ctx).success();
  }

  @Test
  void action_fallsBackToUsernameLookup() {
    formData.putSingle("username", EMAIL);
    UserModel byUsername = mock(UserModel.class);
    when(users.getUserByUsername(realm, EMAIL)).thenReturn(byUsername);

    auth.action(ctx);

    verify(users, never()).addUser(any(), anyString());
    verify(ctx).setUser(byUsername);
    verify(ctx).success();
  }

  @Test
  void action_rejectsInvalidEmail() {
    formData.putSingle("username", "not-an-email");

    auth.action(ctx);

    verify(form).setErrors(any());
    verifyRejected();
  }

  @Test
  void action_rejectsMissingEmail() {
    auth.action(ctx);

    verifyRejected();
  }

  @Test
  void action_rejectsWhenHoneypotFilled_noCreate() {
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "company_url"));
    formData.putSingle("username", EMAIL);
    formData.putSingle("company_url", "http://spam.example");

    auth.action(ctx);

    verifyRejected();
  }

  @Test
  void action_proceedsWhenHoneypotEmpty() {
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "company_url"));
    formData.putSingle("username", EMAIL);
    UserModel created = unknownAddress(EMAIL);

    auth.action(ctx);

    verify(ctx).setUser(created);
    verify(ctx).success();
  }

  @Test
  void action_rejectsWhenCaptchaTokenMissing_noCreate() {
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET, "secret"));
    formData.putSingle("username", EMAIL);

    auth.action(ctx);

    verifyRejected();
  }

  @Test
  void action_rejectsWhenCaptchaInvalid_noCreate() {
    auth = stubbedCaptcha(false);
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET, "secret"));
    formData.putSingle("username", EMAIL);
    formData.putSingle("cf-turnstile-response", "tok");

    auth.action(ctx);

    verifyRejected();
    verify(sideEvent)
        .detail(
            EmailLookupOrCreateAuthenticator.DETAIL_REJECT,
            EmailLookupOrCreateAuthenticator.REJECT_CAPTCHA);
    verify(sideEvent).error(Errors.INVALID_FORM);
  }

  @Test
  void action_proceedsWhenCaptchaValid() {
    auth = stubbedCaptcha(true);
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET, "secret"));
    formData.putSingle("username", EMAIL);
    formData.putSingle("cf-turnstile-response", "tok");
    UserModel created = unknownAddress(EMAIL);

    auth.action(ctx);

    verify(ctx).setUser(created);
    verify(ctx).success();
  }

  @Test
  void action_blankConfigDisablesEveryCheck() {
    withConfig(
        Map.of(
            EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "",
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SITE_KEY, "",
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET, ""));
    formData.putSingle("username", EMAIL);
    UserModel created = unknownAddress(EMAIL);

    auth.action(ctx);

    verify(ctx).setUser(created);
    verify(ctx).success();
  }

  @Test
  void authenticate_setsFormAttributesWhenConfigured() {
    withConfig(
        Map.of(
            EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "website",
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SITE_KEY, "sitekey-123"));

    auth.authenticate(ctx);

    verify(form).setAttribute("honeypotField", "website");
    verify(form).setAttribute("captchaSiteKey", "sitekey-123");
  }

  @Test
  void authenticate_skipsFormAttributesWhenBlank() {
    withConfig(
        Map.of(
            EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "",
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SITE_KEY, ""));

    auth.authenticate(ctx);

    verify(form, never()).setAttribute(eq("honeypotField"), any());
    verify(form, never()).setAttribute(eq("captchaSiteKey"), any());
  }

  @Test
  void action_newUserEmitsRegisterAndReportsSourceAsNew() {
    formData.putSingle("username", EMAIL);
    unknownAddress(EMAIL);

    auth.action(ctx);

    verify(event)
        .detail(
            EmailLookupOrCreateAuthenticator.DETAIL_USER_SOURCE,
            EmailLookupOrCreateAuthenticator.SOURCE_NEW);
    verify(sideEvent).event(EventType.REGISTER);
    verify(sideEvent)
        .detail(Details.REGISTER_METHOD, EmailLookupOrCreateAuthenticator.REGISTER_METHOD);
    verify(sideEvent).detail(Details.EMAIL, EMAIL);
    verify(sideEvent).success();
  }

  @Test
  void action_existingUserReportsSourceAsExisting_noRegister() {
    formData.putSingle("username", EMAIL);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(mock(UserModel.class));

    auth.action(ctx);

    verify(event)
        .detail(
            EmailLookupOrCreateAuthenticator.DETAIL_USER_SOURCE,
            EmailLookupOrCreateAuthenticator.SOURCE_EXISTING);
    verify(sideEvent, never()).event(EventType.REGISTER);
  }

  @Test
  void action_honeypotIsReportedAsARejectedForm() {
    withConfig(Map.of(EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD, "website"));
    formData.putSingle("username", EMAIL);
    formData.putSingle("website", "a-bot-filled-this");

    auth.action(ctx);

    verify(sideEvent)
        .detail(
            EmailLookupOrCreateAuthenticator.DETAIL_REJECT,
            EmailLookupOrCreateAuthenticator.REJECT_HONEYPOT);
    verify(sideEvent).error(Errors.INVALID_FORM);
    verify(ctx, never()).success();
  }

  /** Regression guard: newEvent() would replace the flow's builder and break its LOGIN event. */
  @Test
  void action_neverReplacesTheFlowsEventBuilder() {
    formData.putSingle("username", EMAIL);
    unknownAddress(EMAIL);

    auth.action(ctx);

    verify(ctx, never()).newEvent();
  }

  @Test
  void requiresUser_isFalse() {
    assertFalse(auth.requiresUser());
  }

  /** No user has this address; creating one returns the given mock. */
  private UserModel unknownAddress(String email) {
    UserModel created = mock(UserModel.class);
    when(users.addUser(realm, email)).thenReturn(created);
    return created;
  }

  private void verifyRejected() {
    verify(ctx).challenge(any());
    verify(ctx, never()).success();
    verify(users, never()).addUser(any(), anyString());
  }

  private void withConfig(Map<String, String> config) {
    AuthenticatorConfigModel model = mock(AuthenticatorConfigModel.class);
    when(model.getConfig()).thenReturn(config);
    when(ctx.getAuthenticatorConfig()).thenReturn(model);
  }

  private static EmailLookupOrCreateAuthenticator stubbedCaptcha(boolean result) {
    return new EmailLookupOrCreateAuthenticator() {
      @Override
      boolean verifyCaptcha(
          AuthenticationFlowContext context, String secret, String verifyUrl, String token) {
        return result;
      }
    };
  }
}
