package com.agilefreaks.keycloak.auth;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class EmailLookupOrCreateAuthenticatorFactory implements AuthenticatorFactory {

  public static final String ID = "email-lookup-or-create";
  private static final EmailLookupOrCreateAuthenticator SINGLETON =
      new EmailLookupOrCreateAuthenticator();

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Email Lookup-or-Create";
  }

  @Override
  public String getReferenceCategory() {
    return "email";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[] {Requirement.REQUIRED};
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Collects an email, finds the user or creates a new one, and sets it on the flow "
        + "(passwordless login-or-signup). Pair it before a step that verifies email ownership.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty honeypot =
        new ProviderConfigProperty(
            EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD,
            "Honeypot field name",
            "Name of a hidden form field humans never fill. If a submission carries a value "
                + "for it, the request is dropped. Leave empty to disable. The login theme must "
                + "render an input with this name (it receives a 'honeypotField' form attribute).",
            ProviderConfigProperty.STRING_TYPE,
            "");

    ProviderConfigProperty siteKey =
        new ProviderConfigProperty(
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SITE_KEY,
            "CAPTCHA site key",
            "Public site key passed to the login theme (as the 'captchaSiteKey' form attribute) "
                + "to render the widget. Not used for verification. Leave empty to disable.",
            ProviderConfigProperty.STRING_TYPE,
            "");

    ProviderConfigProperty secret =
        new ProviderConfigProperty(
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET,
            "CAPTCHA secret",
            "Provider secret used to verify the token server-side. When set, a valid token is "
                + "required to proceed. Leave empty to disable CAPTCHA verification.",
            ProviderConfigProperty.PASSWORD,
            "");

    ProviderConfigProperty verifyUrl =
        new ProviderConfigProperty(
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_VERIFY_URL,
            "CAPTCHA verify URL",
            "Provider siteverify endpoint. Defaults to Cloudflare Turnstile.",
            ProviderConfigProperty.STRING_TYPE,
            EmailLookupOrCreateAuthenticator.DEFAULT_VERIFY_URL);

    ProviderConfigProperty responseField =
        new ProviderConfigProperty(
            EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_RESPONSE_FIELD,
            "CAPTCHA response field",
            "Name of the posted form field holding the token. Defaults to Turnstile's "
                + "'cf-turnstile-response' (reCAPTCHA uses 'g-recaptcha-response').",
            ProviderConfigProperty.STRING_TYPE,
            EmailLookupOrCreateAuthenticator.DEFAULT_RESPONSE_FIELD);

    return List.of(honeypot, siteKey, secret, verifyUrl, responseField);
  }

  @Override
  public void init(Config.Scope config) {
    // no-op
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // no-op
  }

  @Override
  public void close() {
    // no-op
  }
}
