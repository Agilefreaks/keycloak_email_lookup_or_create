package com.agilefreaks.keycloak.auth;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

/**
 * Passwordless login-or-signup: looks up the user by email and creates one if none exists, setting
 * it on the flow so the following step can verify ownership (e.g. an email/SMS one-time code or a
 * magic link). The optional {@code set-email-verified} authenticator can mark the email verified
 * once that step succeeds.
 *
 * <p>Works in a browser flow, where it renders the email form and processes the post back, and in a
 * direct grant flow, where the address arrives as the {@code username} form parameter of the token
 * request and errors are returned as OAuth JSON. {@code getFlowPath()} tells the two apart: the
 * resource-owner password grant sets it to {@code token}, and anything else is treated as a form
 * flow, so an unexpected value renders a page rather than leaking one into a token response.
 *
 * <p>The honeypot and CAPTCHA guards only apply to the rendered form; a native client cannot
 * produce either, so rate limiting there belongs to the verification step that follows.
 */
public class EmailLookupOrCreateAuthenticator implements Authenticator {

  static final String FIELD = "username";
  static final String FIELD_EMAIL = "email";

  /** Flow path the resource-owner password grant runs under. Everything else renders a form. */
  static final String FLOW_PATH_TOKEN = "token";

  static final String ERROR_INVALID_REQUEST = "invalid_request";
  static final String ERROR_INVALID_GRANT = "invalid_grant";

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
    if (FLOW_PATH_TOKEN.equals(context.getFlowPath())) {
      // No form to render and no post back to wait for: the address is already in the request.
      directGrant(context);
      return;
    }
    context.challenge(loginForm(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

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

    context.setUser(findOrCreate(context, email));
    context.success();
  }

  /**
   * The direct grant half: the address arrives as a form parameter of the token request, so there
   * is nothing to render and nothing to wait for. Errors are OAuth JSON, matching the shape
   * Keycloak's own direct grant authenticators return.
   */
  private void directGrant(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String raw = firstNonBlank(formData.getFirst(FIELD), formData.getFirst(FIELD_EMAIL));
    if (raw == null) {
      context.failure(
          AuthenticationFlowError.INVALID_USER,
          jsonError(400, ERROR_INVALID_REQUEST, "Missing parameter: " + FIELD));
      return;
    }

    String email = raw.trim().toLowerCase();
    if (!Validation.isEmailValid(email)) {
      context.failure(
          AuthenticationFlowError.INVALID_USER,
          jsonError(400, ERROR_INVALID_REQUEST, "Invalid email address"));
      return;
    }

    UserModel user = findOrCreate(context, email);

    if (!user.isEnabled()) {
      context.failure(
          AuthenticationFlowError.USER_DISABLED,
          jsonError(400, ERROR_INVALID_GRANT, "Invalid user credentials"));
      return;
    }
    if (AuthenticatorUtils.getDisabledByBruteForceEventError(context, user) != null) {
      context.failure(
          AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
          jsonError(400, ERROR_INVALID_GRANT, "Invalid user credentials"));
      return;
    }

    context.setUser(user);
    context.success();
  }

  /** Shared by both flows: the address is already validated and normalized. */
  private UserModel findOrCreate(AuthenticationFlowContext context, String email) {
    // Record the attempted username (used by downstream form headers and login events, and by
    // Keycloak to attribute a brute-force failure).
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
    return user;
  }

  private static Response jsonError(int status, String error, String description) {
    Map<String, String> body = new LinkedHashMap<>();
    body.put("error", error);
    body.put("error_description", description);
    try {
      return Response.status(status)
          .type(MediaType.APPLICATION_JSON_TYPE)
          .entity(JsonSerialization.writeValueAsString(body))
          .build();
    } catch (IOException e) {
      throw new IllegalStateException("could not serialize the error body", e);
    }
  }

  private static String firstNonBlank(String first, String second) {
    if (first != null && !first.isBlank()) {
      return first;
    }
    return (second != null && !second.isBlank()) ? second : null;
  }

  /**
   * Verifies a CAPTCHA token against the provider's siteverify endpoint. Returns
   * true on a confirmed pass. Fails <em>open</em> on a network/parse error so a
   * provider outage cannot block every login — abuse during such a window is
   * still bounded by the honeypot and the downstream OTP send cooldown.
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
      form.setErrors(List.of(new FormMessage(FIELD, error)));
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
