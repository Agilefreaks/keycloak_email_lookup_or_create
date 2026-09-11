package com.agilefreaks.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class EmailLookupOrCreateAuthenticatorFactoryTest {

  private ProviderConfigProperty property(String name) {
    return new EmailLookupOrCreateAuthenticatorFactory().getConfigProperties().stream()
        .filter(p -> p.getName().equals(name))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no config property named " + name));
  }

  /**
   * Regression guard: StripSecretsUtils masks an authenticator config value only when its property
   * reports isSecret(). ProviderConfigProperty.PASSWORD is a UI type and does not set that flag, so
   * without this the secret is stored verbatim in every admin-event representation.
   */
  @Test
  void captchaSecretIsDeclaredSecret() {
    assertTrue(property(EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SECRET).isSecret());
  }

  @Test
  void nonSecretPropertiesStayReadable() {
    assertFalse(property(EmailLookupOrCreateAuthenticator.CONFIG_CAPTCHA_SITE_KEY).isSecret());
    assertFalse(property(EmailLookupOrCreateAuthenticator.CONFIG_HONEYPOT_FIELD).isSecret());
  }
}
