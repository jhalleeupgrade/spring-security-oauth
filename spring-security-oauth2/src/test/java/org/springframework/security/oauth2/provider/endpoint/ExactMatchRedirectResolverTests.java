/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.ExactMatchRedirectResolver;

/**
 * @author Dave Syer
 */
public class ExactMatchRedirectResolverTests {

	private ExactMatchRedirectResolver resolver = new ExactMatchRedirectResolver();
	private BaseClientDetails client = new BaseClientDetails();
	
	{
		client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
	}

	@Test
	public void testRedirectNotMatching() throws Exception {
		assertThrows(RedirectMismatchException.class, () -> {
			Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com"));
			String requestedRedirect = "https://anywhere.com/myendpoint";
			client.setRegisteredRedirectUri(redirectUris);
			assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
		});
	}

	@Test
	public void testRedirectWithNoRegisteredValue() throws Exception {
		assertThrows(InvalidRequestException.class, () -> {
			String requestedRedirect = "https://anywhere.com/myendpoint";
			resolver.resolveRedirect(requestedRedirect, client);
		});
	}

	// As we have one or more registered redirects, the redirect SHOULD be present.
	// If not we should expect a Oauth2Exception.
	@Test
	public void testRedirectWithNoRequestedValue() throws Exception {
		assertThrows(OAuth2Exception.class, () -> {
			Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com", "https://nowhere.com"));
			client.setRegisteredRedirectUri(redirectUris);
			resolver.resolveRedirect(null, client);
		});
	}

}
