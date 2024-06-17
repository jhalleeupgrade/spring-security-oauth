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
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.jwt.codec.Codecs.b64UrlEncode;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createJwt;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createJwtHeader;

/**
 * @author Joe Grandja
 */
public class JwkVerifyingJwtAccessTokenConverterTests {

	@Test
	public void encodeWhenCalledThenThrowJwkException() throws Exception {
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(mock(JwkDefinitionSource.class));

		assertThatThrownBy(() -> accessTokenConverter.encode(null, null))
				.isInstanceOf(JwkException.class)
				.withFailMessage("JWT signing (JWS) is not supported.");
	}

	@Test
	public void decodeWhenKeyIdHeaderMissingThenThrowJwkException() throws Exception {
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(mock(JwkDefinitionSource.class));
		String jwt = createJwt(createJwtHeader(null, null, JwkDefinition.CryptoAlgorithm.RS256));

		assertThatThrownBy(() -> accessTokenConverter.decode(jwt))
				.isInstanceOf(InvalidTokenException.class)
				.withFailMessage("Invalid JWT/JWS: kid or x5t is a required JOSE Header");
	}

	@Test
	public void decodeWhenKeyIdHeaderInvalidThenThrowJwkException() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("invalid-key-id", null, JwkDefinition.CryptoAlgorithm.RS256));

		assertThatThrownBy(() -> accessTokenConverter.decode(jwt))
				.isInstanceOf(InvalidTokenException.class)
				.withFailMessage("Invalid JOSE Header kid (invalid-key-id), x5t (null)");
	}

	// gh-1129
	@Test
	public void decodeWhenJwkAlgorithmNullAndJwtAlgorithmPresentThenDecodeStillSucceeds() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));
		Map<String, Object> decodedJwt = accessTokenConverter.decode(jws);
		assertNotNull(decodedJwt);
	}

	@Test
	public void decodeWhenAlgorithmHeaderMissingThenThrowJwkException() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, null));

		assertThatThrownBy(() -> accessTokenConverter.decode(jwt))
				.isInstanceOf(InvalidTokenException.class)
				.withFailMessage("Invalid JWT/JWS: alg is a required JOSE Header");
	}

	@Test
	public void decodeWhenAlgorithmHeaderDoesNotMatchJwkAlgorithmThenThrowJwkException() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS512));

		assertThatThrownBy(() -> accessTokenConverter.decode(jwt))
				.isInstanceOf(InvalidTokenException.class)
				.withFailMessage("Invalid JOSE Header alg (RS512) " +
						"does not match algorithm associated to JWK with kid (key-id-1)");
	}

	@Test
	public void decodeWhenKidHeaderMissingButX5tHeaderPresentThenDecodeStillSucceeds() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", "x5t-1", null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary(null, "x5t-1")).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader(null, "x5t-1", JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));
		Map<String, Object> decodedJwt = accessTokenConverter.decode(jws);
		assertNotNull(decodedJwt);
	}

	// gh-1522, gh-1852
	@Test
	public void decodeWhenVerifySignatureFailsThenThrowInvalidTokenException() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		doThrow(RuntimeException.class).when(signatureVerifier).verify(any(byte[].class), any(byte[].class));
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));

		assertThatThrownBy(() -> accessTokenConverter.decode(jws))
				.isInstanceOf(InvalidTokenException.class)
				.withFailMessage("Failed to decode/verify JWT/JWS");
	}

	private JwkDefinition createRSAJwkDefinition(String keyId, String x5t, JwkDefinition.CryptoAlgorithm algorithm) {
		return createRSAJwkDefinition(JwkDefinition.KeyType.RSA, keyId, x5t,
				JwkDefinition.PublicKeyUse.SIG, algorithm, "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL", "AQAB");
	}

	private JwkDefinition createRSAJwkDefinition(JwkDefinition.KeyType keyType,
												String keyId,
												String x5t,
												JwkDefinition.PublicKeyUse publicKeyUse,
												JwkDefinition.CryptoAlgorithm algorithm,
												String modulus,
												String exponent) {

		return new RsaJwkDefinition(keyId, x5t, publicKeyUse, algorithm, modulus, exponent);
	}
}