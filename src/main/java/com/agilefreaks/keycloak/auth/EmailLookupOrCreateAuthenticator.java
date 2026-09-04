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
import java.util.Locale;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

/**
 * Passwordless login-or-signup: looks up the user by email and creates one if none exists, leaving
 * proof of ownership to the step that follows.
 *
 * <p>Direct grant is recognised by {@code getFlowPath() == "token"}; anything else is treated as a
 * form flow, so an unexpected value renders a page rather than leaking one into a token response.
 * The honeypot and CAPTCHA apply only to the rendered form — a native client cannot produce
 * either, so rate limiting there belongs to the verification step.
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
  // Kept short: the call blocks a Keycloak worker thread for the whole login submission.
  private static final Duration CAPTCHA_CONNECT_TIMEOUT = Duration.ofSeconds(2);

  private static final Duration CAPTCHA_REQUEST_TIMEOUT = Duration.ofSeconds(3);

  private static final HttpClient HTTP =
      HttpClient.newBuilder().connectTimeout(CAPTCHA_CONNECT_TIMEOUT).build();

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (context.getUser() != null) {
      context.success();
      return;
    }
    if (FLOW_PATH_TOKEN.equals(context.getFlowPath())) {
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
    email = normalize(email);

    String secret = config(context, CONFIG_CAPTCHA_SECRET);
    if (secret != null) {
      String responseField =
          firstNonNull(config(context, CONFIG_CAPTCHA_RESPONSE_FIELD), DEFAULT_RESPONSE_FIELD);
      String verifyUrl =
          firstNonNull(config(context, CONFIG_CAPTCHA_VERIFY_URL), DEFAULT_VERIFY_URL);
      String token = formData.getFirst(responseField);
      if (token == null || token.isBlank()) {
        // Silence is right for a bot, but a secret with no site key renders no widget, so no
        // token is ever posted and every login loops with nothing in the log to say why.
        if (config(context, CONFIG_CAPTCHA_SITE_KEY) == null) {
          LOG.errorf(
              "%s is set but %s is not, so no CAPTCHA widget is rendered and no token can be"
                  + " posted: every submission will be rejected",
              CONFIG_CAPTCHA_SECRET, CONFIG_CAPTCHA_SITE_KEY);
        } else {
          LOG.debugf("No CAPTCHA token in the submission; rejecting");
        }
        context.challenge(loginForm(context, null));
        return;
      }
      if (!verifyCaptcha(context, secret, verifyUrl, token)) {
        LOG.debugf("CAPTCHA verification failed; rejecting submission");
        context.challenge(loginForm(context, null));
        return;
      }
    }

    UserModel user = findOrCreate(context, email);
    if (user == null) {
      context.getEvent().error(Errors.INVALID_REGISTRATION);
      context.challenge(loginForm(context, Messages.INVALID_EMAIL));
      return;
    }

    context.setUser(user);
    context.success();
  }

  private void directGrant(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String raw = firstNonBlank(formData.getFirst(FIELD), formData.getFirst(FIELD_EMAIL));
    if (raw == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      context.failure(
          AuthenticationFlowError.INVALID_USER,
          jsonError(400, ERROR_INVALID_REQUEST, "Missing parameter: " + FIELD));
      return;
    }

    String email = normalize(raw);
    if (!Validation.isEmailValid(email)) {
      context.getEvent().error(Errors.INVALID_REQUEST);
      context.failure(
          AuthenticationFlowError.INVALID_USER,
          jsonError(400, ERROR_INVALID_REQUEST, "Invalid email address"));
      return;
    }

    UserModel user = findOrCreate(context, email);
    if (user == null) {
      context.getEvent().error(Errors.INVALID_REGISTRATION);
      context.failure(
          AuthenticationFlowError.UNKNOWN_USER,
          jsonError(400, ERROR_INVALID_GRANT, "Invalid user credentials"));
      return;
    }

    // Event error first, or the LOGIN_ERROR event carries no reason.
    if (!user.isEnabled()) {
      context.getEvent().error(Errors.USER_DISABLED);
      context.failure(
          AuthenticationFlowError.USER_DISABLED,
          jsonError(400, ERROR_INVALID_GRANT, "Invalid user credentials"));
      return;
    }
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().error(bruteForceError);
      context.failure(
          AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
          jsonError(400, ERROR_INVALID_GRANT, "Invalid user credentials"));
      return;
    }

    context.setUser(user);
    context.success();
  }

  /** Null when the user can neither be found nor created. */
  private UserModel findOrCreate(AuthenticationFlowContext context, String email) {
    // Keycloak attributes a brute-force failure to whatever this note holds.
    context.getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);

    KeycloakSession session = context.getSession();
    RealmModel realm = context.getRealm();

    UserModel user;
    try {
      user = lookup(session, realm, email);
    } catch (ModelDuplicateException e) {
        LOG.warnf(e, "Several users share the address '%s'; cannot pick one", email);
      return null;
    }

    if (user == null) {
      try {
        user = session.users().addUser(realm, email);
        user.setEnabled(true);
        user.setEmail(email);
      } catch (ModelDuplicateException e) {
        // Two requests raced for the same new address; the other one won.
        LOG.debugf("Lost the race creating '%s'; using the existing user", email);
        try {
          user = lookup(session, realm, email);
        } catch (ModelDuplicateException ignored) {
          user = null;
        }
        if (user == null) {
          LOG.warnf(e, "Could not create or find a user for '%s'", email);
          return null;
        }
      }
    } else if (user.getEmail() == null || user.getEmail().isBlank()) {
      // Matched on username: without an address the next step has nothing to verify against.
      user.setEmail(email);
    }
    return user;
  }

  private static UserModel lookup(KeycloakSession session, RealmModel realm, String email) {
    UserModel user = session.users().getUserByEmail(realm, email);
    return user != null ? user : session.users().getUserByUsername(realm, email);
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

  /** Locale-independent: a Turkish default locale maps I to a dotless i. */
  private static String normalize(String email) {
    return email.trim().toLowerCase(Locale.ROOT);
  }

  private static String firstNonBlank(String first, String second) {
    if (first != null && !first.isBlank()) {
      return first;
    }
    return (second != null && !second.isBlank()) ? second : null;
  }

  /**
   * Fails <em>open</em> when the provider cannot be reached or answers with something other than a
   * verdict, so an outage cannot block every login. Fails <em>closed</em> on a URL it cannot use:
   * that never recovers, and the console would go on claiming CAPTCHA was enabled.
   */
  boolean verifyCaptcha(
      AuthenticationFlowContext context, String secret, String verifyUrl, String token) {
    HttpRequest request;
    try {
      String body =
          "secret=" + enc(secret)
              + "&response=" + enc(token)
              + "&remoteip=" + enc(context.getConnection().getRemoteAddr());
      request =
          HttpRequest.newBuilder(URI.create(verifyUrl))
              .timeout(CAPTCHA_REQUEST_TIMEOUT)
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build();
    } catch (IllegalArgumentException e) {
      LOG.errorf(
          e, "CAPTCHA verify URL '%s' is not usable; rejecting the submission", verifyUrl);
      return false;
    }

    try {
      HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        LOG.warnf(
            "CAPTCHA verifier returned HTTP %d; allowing submission", response.statusCode());
        return true;
      }
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
  }

  @Override
  public void close() {
  }
}
