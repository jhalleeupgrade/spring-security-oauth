/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.oauth2.provider.token;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DefaultAuthenticationKeyGeneratorTest {
    private static final String USERNAME = "name";
    private static final String CLIENT_ID = "client-id";
    private static final String CHECKSUM = "checksum";
    @Mock
    private OAuth2Authentication auth;
    @Spy
    private DefaultAuthenticationKeyGenerator generator;

    @Test
    public void shouldUseTheChecksumGeneratedByTheDigest() {
        when(auth.getOAuth2Request()).thenReturn(createRequest(CLIENT_ID));
        when(auth.getName()).thenReturn(USERNAME);

        when(generator.generateKey(anyMap())).thenReturn(CHECKSUM);

        assertEquals(CHECKSUM, generator.extractKey(auth));
    }

    @Test
    public void shouldOnlyUseTheClientIdAsPartOfTheDigestIfTheAuthIsClientOnly() {
        when(auth.isClientOnly()).thenReturn(true);
        when(auth.getOAuth2Request()).thenReturn(createRequest(CLIENT_ID));

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "");
        verify(generator).generateKey(expectedValues);
    }

    @Test
    public void shouldNotUseScopesIfNoneAreProvided() {
        when(auth.getOAuth2Request()).thenReturn(createRequest(CLIENT_ID));
        when(auth.getName()).thenReturn(USERNAME);

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("username", USERNAME);
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "");
        verify(generator).generateKey(expectedValues);
    }

    @Test
    public void shouldSortTheScopesBeforeDigesting() {
        when(auth.getOAuth2Request()).thenReturn(createRequest(CLIENT_ID, "3", "1", "2"));
        when(auth.getName()).thenReturn(USERNAME);

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("username", USERNAME);
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "1 2 3");
        verify(generator).generateKey(expectedValues);
    }

    private OAuth2Request createRequest(String clientId, String... scopes) {
        Set<String> scopeSet = null;
        if (scopes.length > 0) {
            scopeSet = new LinkedHashSet<String>(Arrays.asList(scopes));
        }

        return new OAuth2Request(
                Collections.<String, String>emptyMap(),
                clientId,
                Collections.<GrantedAuthority>emptyList(),
                true,
                scopeSet,
                Collections.<String>emptySet(),
                "redirect-uri",
                Collections.<String>emptySet(),
                Collections.<String, Serializable>emptyMap()
        );
    }
}