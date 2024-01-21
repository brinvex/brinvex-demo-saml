/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bx_example;

import org.apache.commons.lang3.Validate;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

@Configuration
public class BxSecurityConfiguration {

    @Value("${saml.ap.entityId}")
    private String apEntityId;

    @Value("${saml.ap.certificate}")
    private Resource apCert;

    @Value("${saml.ap.ssoLocation}")
    private String apSsoLocation;

    @Value("${saml.ap.sloLocation}")
    private String apSloLocation;

    @Value("${saml.rp.registrationId}")
    private String rpRegistrationId;

    @Value("${saml.rp.certificate}")
    private Resource rpCert;

    @Value("${saml.rp.certificate-private-key}")
    private Resource rpCertPrivateKey;

    @Value("${saml.rp.assertionConsumerServiceLocation}")
    private String rpAssertionConsumerServiceLocation;

    @Value("${saml.rp.sloLocation}")
    private String rpSloLocation;

    @Value("${saml.usernameAttrKey}")
    private String usernameAttrKey;

    @Value("${saml.loginProcessingUrl}")
    private String loginProcessingUrl;

    @Value("${saml.logoutUrl}")
    private String logoutUrl;

    public static class CustomSaml2AuthenticatedPrincipal extends DefaultSaml2AuthenticatedPrincipal {

        private final String appUserName;

        public CustomSaml2AuthenticatedPrincipal(
                DefaultSaml2AuthenticatedPrincipal defaultSaml2AuthenticatedPrincipal,
                String appUserName
        ) {
            super(
                    defaultSaml2AuthenticatedPrincipal.getName(),
                    defaultSaml2AuthenticatedPrincipal.getAttributes(),
                    defaultSaml2AuthenticatedPrincipal.getSessionIndexes()
            );
            this.setRelyingPartyRegistrationId(defaultSaml2AuthenticatedPrincipal.getRelyingPartyRegistrationId());
            this.appUserName = appUserName;
        }

        public String getAppUserName() {
            return this.appUserName;
        }

        @Override
        public String toString() {
            String name = getName();
            return new StringJoiner("/", "CustomSaml2AuthPrincipal[", "]")
                    .add(getAppUserName())
                    .add(name == null ? "null" : name.substring(0, 24))
                    .toString();
        }
    }

    @Bean
    public OpenSaml4AuthenticationProvider samlAuthenticationProvider() {
        OpenSaml4AuthenticationProvider samlAuthenticationProvider = new OpenSaml4AuthenticationProvider();
        samlAuthenticationProvider.setAssertionValidator(OpenSaml4AuthenticationProvider
                .createDefaultAssertionValidatorWithParameters(assertionToken ->
                        assertionToken.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(10).toMillis()))
        );

        samlAuthenticationProvider.setResponseAuthenticationConverter(respToken -> {
            Saml2Authentication defaultSamlAuth = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter()
                    .convert(respToken);
            if (defaultSamlAuth != null) {
                DefaultSaml2AuthenticatedPrincipal defaultSamlAuthPrincipal = (DefaultSaml2AuthenticatedPrincipal) defaultSamlAuth.getPrincipal();
                Map<String, List<Object>> attributes = defaultSamlAuthPrincipal.getAttributes();
                List<Object> userNameAttrValues = attributes.get(this.usernameAttrKey);
                String username = userNameAttrValues == null || userNameAttrValues.isEmpty() ? null : String.valueOf(userNameAttrValues.get(0));
                CustomSaml2AuthenticatedPrincipal customSaml2AuthenticatedPrincipal = new CustomSaml2AuthenticatedPrincipal(
                        defaultSamlAuthPrincipal,
                        username
                );
                return new Saml2Authentication(
                        customSaml2AuthenticatedPrincipal,
                        defaultSamlAuth.getSaml2Response(),
                        defaultSamlAuth.getAuthorities());
            }
            return null;
        });

        return samlAuthenticationProvider;
    }

    @Bean
    SecurityFilterChain httpConf(HttpSecurity httpSecConf) throws Exception {
        httpSecConf.headers(headerConf -> headerConf.frameOptions(FrameOptionsConfig::disable));
        httpSecConf.csrf(AbstractHttpConfigurer::disable);
        httpSecConf.authorizeHttpRequests(authConf -> authConf.anyRequest().authenticated());

        httpSecConf.saml2Login(samlLoginConf -> {
            samlLoginConf.loginProcessingUrl(this.loginProcessingUrl);
            samlLoginConf.authenticationManager(new ProviderManager(samlAuthenticationProvider()));
        });

        httpSecConf.saml2Logout(samlLogoutConf -> {
                    samlLogoutConf.logoutUrl("/logout");
                    samlLogoutConf.logoutRequest(samlLogoutReqConf -> {
                        samlLogoutReqConf.logoutUrl(this.logoutUrl);
                        OpenSaml4LogoutRequestResolver logoutRequestResolver = new OpenSaml4LogoutRequestResolver(rpRegRepository());
                        logoutRequestResolver.setParametersConsumer(p -> {
                            LogoutRequest logoutRequest = p.getLogoutRequest();
                            NameID nameId = logoutRequest.getNameID();
                            nameId.setSPNameQualifier(this.rpRegistrationId);
                            nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
                            Saml2Authentication authentication = (Saml2Authentication) p.getAuthentication();
                            CustomSaml2AuthenticatedPrincipal principal = (CustomSaml2AuthenticatedPrincipal) authentication.getPrincipal();
                            nameId.setValue(principal.getName());
                        });
                        samlLogoutReqConf.logoutRequestResolver(logoutRequestResolver);
                    });
                })
                .saml2Metadata(Customizer.withDefaults());

        return httpSecConf.build();
    }

    @Bean
    RelyingPartyRegistrationRepository rpRegRepository() {
        RelyingPartyRegistration rp =
                RelyingPartyRegistration.withRegistrationId(this.rpRegistrationId)
                        .entityId("{registrationId}")

                        .signingX509Credentials((c) -> c.add(Saml2X509Credential.signing(
                                loadPkcs8PrivateKey(this.rpCertPrivateKey),
                                loadX509Cert(this.rpCert))))
                        .decryptionX509Credentials((c) -> c.add(Saml2X509Credential.decryption(
                                loadPkcs8PrivateKey(this.rpCertPrivateKey),
                                loadX509Cert(this.rpCert))))
                        .assertionConsumerServiceLocation(this.rpAssertionConsumerServiceLocation)
                        .authnRequestsSigned(false)
                        .assertingPartyDetails(ap -> {

                            ap.entityId(this.apEntityId);
                            ap.singleSignOnServiceLocation(this.apSsoLocation);
                            ap.singleSignOnServiceBinding(Saml2MessageBinding.POST);
                            ap.verificationX509Credentials(c -> c.add(Saml2X509Credential.verification(
                                    loadX509Cert(this.apCert))));

                            ap.singleLogoutServiceBinding(Saml2MessageBinding.POST);
                            ap.singleLogoutServiceLocation(this.apSloLocation);
                            ap.singleLogoutServiceResponseLocation(this.apSloLocation);
                        })
                        .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                        .singleLogoutServiceLocation(this.rpSloLocation)
                        .singleLogoutServiceResponseLocation(this.rpSloLocation)

                        .build();
        return new InMemoryRelyingPartyRegistrationRepository(rp);
    }

    X509Certificate loadX509Cert(Resource resource) {
        try (InputStream is = resource.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

    RSAPrivateKey loadPkcs8PrivateKey(Resource location) {
        Validate.isTrue(location != null, "No private key location specified");
        Validate.isTrue(location.exists(), "Private key location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}
