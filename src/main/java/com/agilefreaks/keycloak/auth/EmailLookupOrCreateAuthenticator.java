package com.agilefreaks.keycloak.auth;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

/**
 * Passwordless login-or-signup: renders the email form, then looks up the user
 * by email and creates one if none exists, setting it on the flow so the
 * following step can verify ownership (e.g. an email/SMS one-time code or a
 * magic link). The optional {@code set-email-verified} authenticator can mark
 * the email verified once that step succeeds.
 *
 * <p>Two optional abuse checks run before any user is created or downstream
 * step fires, both off unless configured (see the factory's config properties):
 * a honeypot field (reject submissions that filled a field humans never see)
 * and a CAPTCHA token verified server-side (Cloudflare Turnstile / reCAPTCHA).
 */
public class EmailLookupOrCreateAuthenticator implements Authenticator {

  static final String FIELD = "username";

  static final String CONFIG_HONEYPOT_FIELD = "honeypotField";
  static final String CONFIG_CAPTCHA_SITE_KEY = "captchaSiteKey";
  static final String CONFIG_CAPTCHA_SECRET = "captchaSecret";
  static final String CONFIG_CAPTCHA_VERIFY_URL = "captchaVerifyUrl";
  static final String CONFIG_CAPTCHA_RESPONSE_FIELD = "captchaResponseField";

  static final String DEFAULT_VERIFY_URL =
      "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  static final String DEFAULT_RESPONSE_FIELD = "cf-turnstile-response";

  private static final Logger LOG = Logger.getLogger(EmailLookupOrCreateAuthenticator.class);
  private static final HttpClient HTTP =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // A cookie (or upstream step) may already have identified the user.
    if (context.getUser() != null) {
      context.success();
      return;
    }
    context.challenge(loginForm(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    // Honeypot: a hidden field humans never see. If it carries a value, a bot
    // filled it — re-render without creating a user or triggering the next step.
    String honeypotField = config(context, CONFIG_HONEYPOT_FIELD);
    if (honeypotField != null) {
      String trap = formData.getFirst(honeypotField);
      if (trap != null && !trap.isBlank()) {
        LOG.debugf("Honeypot field '%s' filled; rejecting submission", honeypotField);
        context.challenge(loginForm(context, null));
        return;
      }
    }

    String email = formData.getFirst(FIELD);
    if (email == null || email.trim().isEmpty() || !Validation.isEmailValid(email.trim())) {
      context.challenge(loginForm(context, Messages.INVALID_EMAIL));
      return;
    }
    email = email.trim().toLowerCase();

    // CAPTCHA: verify the token server-side before any user is created.
    String secret = config(context, CONFIG_CAPTCHA_SECRET);
    if (secret != null) {
      String responseField =
          firstNonNull(config(context, CONFIG_CAPTCHA_RESPONSE_FIELD), DEFAULT_RESPONSE_FIELD);
      String verifyUrl =
          firstNonNull(config(context, CONFIG_CAPTCHA_VERIFY_URL), DEFAULT_VERIFY_URL);
      String token = formData.getFirst(responseField);
      if (token == null || token.isBlank() || !verifyCaptcha(context, secret, verifyUrl, token)) {
        LOG.debugf("CAPTCHA verification failed; rejecting submission");
        context.challenge(loginForm(context, null));
        return;
      }
    }

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

  /**
   * Verifies a CAPTCHA token against the provider's siteverify endpoint. Returns
   * true on a confirmed pass. Fails <em>open</em> on a network/parse error so a
   * provider outage cannot block every login — abuse during such a window is
   * still bounded by the honeypot and the downstream OTP send cooldown.
   *
   * <p>Package-protected and non-final so tests can stub it without a network call.
   */
  boolean verifyCaptcha(
      AuthenticationFlowContext context, String secret, String verifyUrl, String token) {
    try {
      String body =
          "secret=" + enc(secret)
              + "&response=" + enc(token)
              + "&remoteip=" + enc(context.getConnection().getRemoteAddr());
      HttpRequest request =
          HttpRequest.newBuilder(URI.create(verifyUrl))
              .timeout(Duration.ofSeconds(8))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build();
      HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
      JsonNode json = JsonSerialization.mapper.readTree(response.body());
      return json.path("success").asBoolean(false);
    } catch (Exception e) {
      LOG.warnf(e, "CAPTCHA verification call failed; allowing submission");
      return true;
    }
  }

  private Response loginForm(AuthenticationFlowContext context, String error) {
    var form = context.form();
    String honeypotField = config(context, CONFIG_HONEYPOT_FIELD);
    if (honeypotField != null) {
      form.setAttribute("honeypotField", honeypotField);
    }
    String siteKey = config(context, CONFIG_CAPTCHA_SITE_KEY);
    if (siteKey != null) {
      form.setAttribute("captchaSiteKey", siteKey);
    }
    if (error != null) {
      form.setError(error);
    }
    return form.createLoginUsername();
  }

  private static String config(AuthenticationFlowContext context, String key) {
    AuthenticatorConfigModel model = context.getAuthenticatorConfig();
    if (model == null || model.getConfig() == null) {
      return null;
    }
    String value = model.getConfig().get(key);
    return (value != null && !value.isBlank()) ? value.trim() : null;
  }

  private static String firstNonNull(String a, String b) {
    return a != null ? a : b;
  }

  private static String enc(String value) {
    return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
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
