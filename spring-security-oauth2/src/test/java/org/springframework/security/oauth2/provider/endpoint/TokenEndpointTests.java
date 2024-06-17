/*
 * Copyright 2002-2011 the original author or authors.
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

package org.springframework.security.oauth2.provider.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class TokenEndpointTests {

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private String clientId = "client";
    private BaseClientDetails clientDetails = new BaseClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("client", null,
            Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
        return request;
    }

    @BeforeEach
    public void init() {
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setClientId(clientId);
    }

    @Test
    public void testGetAccessTokenWithScope() throws HttpRequestMethodNotSupportedException {

        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<String, String>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

        when(tokenGranter.grant(eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        OAuth2AccessToken body = response.getBody();
        assertEquals(body, expectedToken);
        assertTrue(body.getTokenType() != null, "Wrong body: " + body);
        assertTrue(captor.getValue().getScope().isEmpty(), "Scope of token request not cleared");
    }

    @Test
    public void testGetAccessTokenWithUnsupportedRequestParameters() throws HttpRequestMethodNotSupportedException {
		assertThrows(HttpRequestMethodNotSupportedException.class, () -> {
			endpoint.getAccessToken(clientAuthentication, new HashMap<String, String>());
		});
	}

    @Test
    public void testImplicitGrant() throws HttpRequestMethodNotSupportedException {
		assertThrows(InvalidGrantException.class, () -> {
			HashMap<String, String> parameters = new HashMap<String, String>();
			parameters.put(OAuth2Utils.GRANT_TYPE, "implicit");
			parameters.put("client_id", clientId);
			parameters.put("scope", "read");
			@SuppressWarnings("unchecked")
			Map<String, String> anyMap = any(Map.class);
			when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
					createFromParameters(parameters));
			when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);
			endpoint.postAccessToken(clientAuthentication, parameters);
		});
	}

    // gh-1268
    @Test
    public void testGetAccessTokenReturnsHeaderContentTypeJson() throws Exception {
        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<String, String>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("application/json;charset=UTF-8", response.getHeaders().get("Content-Type").iterator().next());
    }

    @Test
    public void testRefreshTokenGrantTypeWithoutRefreshTokenParameter() throws Exception {
		assertThrows(InvalidRequestException.class, () -> {
			when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

			HashMap<String, String> parameters = new HashMap<String, String>();
			parameters.put("client_id", clientId);
			parameters.put("scope", "read");
			parameters.put("grant_type", "refresh_token");

			when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
					createFromParameters(parameters));

			endpoint.postAccessToken(clientAuthentication, parameters);
		});
	}

    @Test
    public void testGetAccessTokenWithRefreshToken() throws Exception {
        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<String, String>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("refresh_token"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertEquals(expectedToken, response.getBody());
    }
}
