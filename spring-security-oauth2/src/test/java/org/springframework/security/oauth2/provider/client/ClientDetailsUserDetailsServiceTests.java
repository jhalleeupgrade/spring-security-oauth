/*
 * Copyright 2013 the original author or authors.
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

package org.springframework.security.oauth2.provider.client;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.Map;

/**
 * @author Ruslan Forostianov
 */
public class ClientDetailsUserDetailsServiceTests {

	@SuppressWarnings("unchecked")
	@Test
	public void shouldThrowUsernameNotFoundExceptionWhenNoSuchClient() throws Exception {
		assertThrows(UsernameNotFoundException.class, () -> {

			Map<String, Object> map = new HashMap<String, Object>();
			map.put(UserAuthenticationConverter.USERNAME, "test_user");

			ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
			Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(NoSuchClientException.class);
			ClientDetailsUserDetailsService testee = new ClientDetailsUserDetailsService(clientDetailsService);

			testee.loadUserByUsername("test_user");
		});
	}

	@SuppressWarnings("unchecked")
	@Test
	public void shouldConductOriginalException() throws Exception {
		assertThrows(ClientRegistrationException.class, () -> {

			Map<String, Object> map = new HashMap<String, Object>();
			map.put(UserAuthenticationConverter.USERNAME, "test_user");

			ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
			Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(ClientRegistrationException.class);
			ClientDetailsUserDetailsService testee = new ClientDetailsUserDetailsService(clientDetailsService);

			testee.loadUserByUsername("test_user");
		});
	}

}
