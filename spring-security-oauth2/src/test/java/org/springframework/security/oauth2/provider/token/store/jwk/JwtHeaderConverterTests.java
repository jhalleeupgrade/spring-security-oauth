/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;


import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createDefaultJwtPayload;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createJwt;

/**
 * Tests for {@link JwtHeaderConverter}.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 */
public class JwtHeaderConverterTests {
    private final JwtHeaderConverter converter = new JwtHeaderConverter();

    @Test
    public void convertWhenJwtTokenIsNullThenThrowNullPointerException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    public void convertWhenJwtTokenInvalidThenThrowJwkException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert(""))
                .isInstanceOf(InvalidTokenException.class)
                .withFailMessage("Invalid JWT. Missing JOSE Header.");
    }

    @Test
    public void convertWhenJwtTokenValidThenReturnJwtHeaders() throws Exception {
        Map<String, String> jwtHeaders = this.converter.convert(createJwt());
        assertEquals("key-id-1", jwtHeaders.get(JwkAttributes.KEY_ID));
        assertEquals(JwkDefinition.CryptoAlgorithm.RS256.headerParamValue(), jwtHeaders.get(JwkAttributes.ALGORITHM));
    }

    @Test
    public void convertWhenJwtTokenWithMalformedHeaderThenThrowJwkException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert("f." + new String(createDefaultJwtPayload())))
                .isInstanceOf(InvalidTokenException.class)
                .withFailMessage("Invalid JWT. Missing JOSE Header.");
    }

}
