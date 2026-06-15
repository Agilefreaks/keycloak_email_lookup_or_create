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
    return false;
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
    return List.of();
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
