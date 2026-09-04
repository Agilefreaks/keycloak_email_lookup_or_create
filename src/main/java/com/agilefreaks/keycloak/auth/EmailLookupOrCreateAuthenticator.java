package com.agilefreaks.keycloak.auth;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

/**
 * Passwordless login-or-signup: looks up the user by email and creates one if none exists, leaving
 * proof of ownership to the step that follows.
 *
 * <p>Only {@code getFlowPath() == "token"} (the resource-owner password grant) answers OAuth JSON.
 * Anything else renders the form, so an unexpected value shows a page rather than leaking one into
 * a token response. The honeypot and CAPTCHA apply to the rendered form only.
 */
public class EmailLookupOrCreateAuthenticator implements Authenticator {

  static final String FIELD = "username";
  static final String FIELD_EMAIL = "email";
  static final String FLOW_PATH_TOKEN = "token";

  static final String CONFIG_HONEYPOT_FIELD = "honeypotField";
  static final String CONFIG_CAPTCHA_SITE_KEY = "captchaSiteKey";
  static final String CONFIG_CAPTCHA_SECRET = "captchaSecret";
  static final String CONFIG_CAPTCHA_VERIFY_URL = "captchaVerifyUrl";
  static final String CONFIG_CAPTCHA_RESPONSE_FIELD = "captchaResponseField";

  static final String DEFAULT_VERIFY_URL =
      "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  static final String DEFAULT_RESPONSE_FIELD = "cf-turnstile-response";

  private static final String INVALID_CREDENTIALS = "Invalid user credentials";

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
    } else if (FLOW_PATH_TOKEN.equals(context.getFlowPath())) {
      directGrant(context);
    } else {
      context.challenge(loginForm(context, null));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (honeypotFilled(context, formData)) {
      context.challenge(loginForm(context, null));
      return;
    }

    String email = normalize(formData.getFirst(FIELD));
    if (!Validation.isEmailValid(email)) {
      context.challenge(loginForm(context, Messages.INVALID_EMAIL));
      return;
    }

    if (!captchaPassed(context, formData)) {
      context.challenge(loginForm(context, null));
      return;
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
    String email = normalize(formData.getFirst(FIELD));
    if (email.isEmpty()) {
      email = normalize(formData.getFirst(FIELD_EMAIL));
    }
    if (email.isEmpty()) {
      refuse(context, Errors.USER_NOT_FOUND, AuthenticationFlowError.INVALID_USER,
          OAuthErrorException.INVALID_REQUEST, "Missing parameter: " + FIELD);
      return;
    }
    if (!Validation.isEmailValid(email)) {
      refuse(context, Errors.INVALID_REQUEST, AuthenticationFlowError.INVALID_USER,
          OAuthErrorException.INVALID_REQUEST, "Invalid email address");
      return;
    }

    UserModel user = findOrCreate(context, email);
    if (user == null) {
      refuse(context, Errors.INVALID_REGISTRATION, AuthenticationFlowError.UNKNOWN_USER,
          OAuthErrorException.INVALID_GRANT, INVALID_CREDENTIALS);
      return;
    }
    if (!user.isEnabled()) {
      refuse(context, Errors.USER_DISABLED, AuthenticationFlowError.USER_DISABLED,
          OAuthErrorException.INVALID_GRANT, INVALID_CREDENTIALS);
      return;
    }
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      refuse(context, bruteForceError, AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
          OAuthErrorException.INVALID_GRANT, INVALID_CREDENTIALS);
      return;
    }

    context.setUser(user);
    context.success();
  }

  private static void refuse(
      AuthenticationFlowContext context,
      String eventError,
      AuthenticationFlowError flowError,
      String oauthError,
      String description) {
    // Event error first, or the LOGIN_ERROR event carries no reason.
    context.getEvent().error(eventError);
    context.failure(
        flowError,
        Response.status(400)
            .type(MediaType.APPLICATION_JSON_TYPE)
            .entity(new OAuth2ErrorRepresentation(oauthError, description))
            .build());
  }

  /** Null when the user can neither be found nor created. */
  private static UserModel findOrCreate(AuthenticationFlowContext context, String email) {
    // Keycloak attributes a brute-force failure to whatever this note holds.
    context.getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);

    UserProvider users = context.getSession().users();
    RealmModel realm = context.getRealm();
    try {
      UserModel user = lookup(users, realm, email);
      if (user == null) {
        return create(users, realm, email);
      }
      if (user.getEmail() == null || user.getEmail().isBlank()) {
        // Matched on username: without an address the next step has nothing to verify against.
        user.setEmail(email);
      }
      return user;
    } catch (ModelDuplicateException e) {
      LOG.warnf(e, "Several users share the address '%s'; cannot pick one", email);
      return null;
    }
  }

  private static UserModel create(UserProvider users, RealmModel realm, String email) {
    try {
      UserModel user = users.addUser(realm, email);
      user.setEnabled(true);
      user.setEmail(email);
      return user;
    } catch (ModelDuplicateException e) {
      // Two requests raced for the same new address; the other one won.
      LOG.debugf("Lost the race creating '%s'; using the existing user", email);
      UserModel winner = lookup(users, realm, email);
      if (winner == null) {
        LOG.warnf(e, "Could not create or find a user for '%s'", email);
      }
      return winner;
    }
  }

  private static UserModel lookup(UserProvider users, RealmModel realm, String email) {
    UserModel user = users.getUserByEmail(realm, email);
    return user != null ? user : users.getUserByUsername(realm, email);
  }

  /** Locale-independent: a Turkish default locale maps I to a dotless i. Null becomes empty. */
  private static String normalize(String email) {
    return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
  }

  private static boolean honeypotFilled(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    String field = config(context, CONFIG_HONEYPOT_FIELD);
    String trap = field == null ? null : formData.getFirst(field);
    if (trap == null || trap.isBlank()) {
      return false;
    }
    LOG.debugf("Honeypot field '%s' filled; rejecting submission", field);
    return true;
  }

  /** True when CAPTCHA is off or the posted token verifies. */
  private boolean captchaPassed(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    String secret = config(context, CONFIG_CAPTCHA_SECRET);
    if (secret == null) {
      return true;
    }
    String responseField =
        Objects.requireNonNullElse(
            config(context, CONFIG_CAPTCHA_RESPONSE_FIELD), DEFAULT_RESPONSE_FIELD);
    String token = formData.getFirst(responseField);
    if (token == null || token.isBlank()) {
      if (config(context, CONFIG_CAPTCHA_SITE_KEY) == null) {
        // Without a site key the theme renders no widget, so no token is ever posted and every
        // login loops with nothing in the log to say why.
        LOG.errorf(
            "%s is set but %s is not, so no CAPTCHA widget is rendered and no token can be"
                + " posted: every submission will be rejected",
            CONFIG_CAPTCHA_SECRET, CONFIG_CAPTCHA_SITE_KEY);
      } else {
        LOG.debugf("No CAPTCHA token in the submission; rejecting");
      }
      return false;
    }
    String verifyUrl =
        Objects.requireNonNullElse(config(context, CONFIG_CAPTCHA_VERIFY_URL), DEFAULT_VERIFY_URL);
    if (verifyCaptcha(context, secret, verifyUrl, token)) {
      return true;
    }
    LOG.debugf("CAPTCHA verification failed; rejecting submission");
    return false;
  }

  /**
   * Fails <em>open</em> when the provider cannot be reached or answers with something other than a
   * verdict, so an outage cannot block every login. Fails <em>closed</em> on a URL it cannot use:
   * that never recovers, and the console would go on claiming CAPTCHA was enabled.
   */
  boolean verifyCaptcha(
      AuthenticationFlowContext context, String secret, String verifyUrl, String token) {
    String body =
        "secret=" + enc(secret)
            + "&response=" + enc(token)
            + "&remoteip=" + enc(context.getConnection().getRemoteAddr());
    HttpRequest request;
    try {
      request =
          HttpRequest.newBuilder(URI.create(verifyUrl))
              .timeout(CAPTCHA_REQUEST_TIMEOUT)
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build();
    } catch (IllegalArgumentException e) {
      LOG.errorf(e, "CAPTCHA verify URL '%s' is not usable; rejecting the submission", verifyUrl);
      return false;
    }

    try {
      HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        LOG.warnf("CAPTCHA verifier returned HTTP %d; allowing submission", response.statusCode());
        return true;
      }
      return JsonSerialization.mapper.readTree(response.body()).path("success").asBoolean(false);
    } catch (Exception e) {
      LOG.warnf(e, "CAPTCHA verification call failed; allowing submission");
      return true;
    }
  }

  private static String enc(String value) {
    return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
  }

  private static Response loginForm(AuthenticationFlowContext context, String error) {
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

  /** The trimmed value, or null when unset or blank. */
  private static String config(AuthenticationFlowContext context, String key) {
    AuthenticatorConfigModel model = context.getAuthenticatorConfig();
    if (model == null || model.getConfig() == null) {
      return null;
    }
    String value = model.getConfig().get(key);
    return (value == null || value.isBlank()) ? null : value.trim();
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
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
