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
package org.springframework.security.jwt;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.jwt.JwtSpecData.D;
import static org.springframework.security.jwt.JwtSpecData.E;
import static org.springframework.security.jwt.JwtSpecData.N;

import java.util.Collections;
import java.util.Map;

import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;

import org.junit.jupiter.api.Test;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;

/**
 * @author Luke Taylor
 */
public class JwtTests {
	/**
	 * Sample from the JWT spec.
	 */
	static final String JOE_CLAIM_SEGMENT = "{\"iss\":\"joe\",\r\n" + " \"exp\":1300819380,\r\n"
			+ " \"https://example.com/is_root\":true}";
	static final String JOE_HEADER_HMAC = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS256\"}";
	static final String JOE_HMAC_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
			+ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
			+ "SfgggA-oZk7ztlq1i8Uz5VhmPmustakoDa9wAf8uHyQ";
	static final String JOE_HMAC_TOKEN_NO_TYP = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
			+ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
			+ "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	static final String JOE_RSA_TOKEN = "eyJhbGciOiJSUzI1NiJ9."
			+ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
			+ "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds"
			+ "9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZR"
			+ "mB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs9"
			+ "8rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
	static final MacSigner hmac = new MacSigner(JwtSpecData.HMAC_KEY);

	@Test
	public void defaultTokenContainsType() throws Exception {
		Jwt token = JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac);
		assertTrue(token.toString().contains("\"alg\":\"HS256\",\"typ\":\"JWT\""), "Wrong header: " + token);
	}

	@Test
	public void inspectCustomHeaders() throws Exception {
		Map<String, String> headers = JwtHelper.headers(
				JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac, Collections.singletonMap("foo", "bar")).getEncoded());
		assertEquals("bar", headers.get("foo"), "Wrong header: " + headers);
		assertEquals("HS256", headers.get("alg"), "Wrong header: " + headers);
		assertEquals("JWT", headers.get("typ"), "Wrong header: " + headers);
	}

	@Test
	public void inspectHeaders() throws Exception {
		Map<String, String> headers = JwtHelper.headers(JOE_RSA_TOKEN);
		assertEquals("RS256", headers.get("alg"), "Wrong header: " + headers);
		assertEquals("JWT", headers.get("typ"), "Wrong header: " + headers);
	}

	@Test
	public void roundTripCustomHeaders() throws Exception {
		Jwt token = JwtHelper
				.decode(JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac, Collections.singletonMap("foo", "bar")).getEncoded());
		assertTrue(token.toString().contains("\"foo\":\"bar\""), "Wrong header: " + token);
	}

	@Test
	public void roundTripClaims() throws Exception {
		Jwt token = JwtHelper.decode(JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac).getEncoded());
		assertTrue(token.toString().contains("\"alg\":\"HS256\",\"typ\":\"JWT\""), "Wrong header: " + token);
	}

	@Test
	public void tokenWithNoTypeCanBeDecoded() throws Exception {
		Jwt token = JwtHelper.decode(JOE_HMAC_TOKEN_NO_TYP);
		assertEquals(JOE_HMAC_TOKEN_NO_TYP, token.getEncoded());
	}

	@Test
	public void tokenBytesCreateSameToken() throws Exception {
		Jwt token = JwtHelper.decode(JOE_HMAC_TOKEN);
		assertEquals(JOE_HMAC_TOKEN, new String(token.bytes(), "UTF-8"));
		assertEquals(JOE_HMAC_TOKEN, token.getEncoded());
	}

	@Test
	public void expectedClaimsValueIsReturned() {
		Jwt token = JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac);
		assertEquals(JOE_CLAIM_SEGMENT, JwtHelper.decode(token.getEncoded()).getClaims());
	}

	@Test
	public void hmacSignedTokenParsesAndVerifies() {
		JwtHelper.decode(JOE_HMAC_TOKEN).verifySignature(hmac);
	}

	@Test
	public void invalidHmacSignatureRaisesException() {
		assertThrows(InvalidSignatureException.class, () -> {
			JwtHelper.decode(JOE_HMAC_TOKEN).verifySignature(new MacSigner("differentkey".getBytes()));
		});
	}

	@Test
	public void tokenMissingSignatureIsRejected() {
		assertThrows(IllegalArgumentException.class, () -> {
			JwtHelper.decode(JOE_HMAC_TOKEN.substring(0, JOE_HMAC_TOKEN.lastIndexOf('.') + 1));
		});
	}

	@Test
	public void hmacVerificationIsInverseOfSigning() {
		Jwt jwt = JwtHelper.encode(JOE_CLAIM_SEGMENT, hmac);
		jwt.verifySignature(hmac);
		assertEquals(JOE_CLAIM_SEGMENT, jwt.getClaims());
	}

	@Test
	public void rsaSignedTokenParsesAndVerifies() {
		Jwt jwt = JwtHelper.encode(JOE_CLAIM_SEGMENT, new RsaSigner(N, E));
		jwt.verifySignature(new RsaVerifier(N, D));
		assertEquals(JOE_CLAIM_SEGMENT, jwt.getClaims());
	}

	@Test
	public void invalidRsaSignatureRaisesException() {
		assertThrows(InvalidSignatureException.class, () -> {
			JwtHelper.decodeAndVerify(JOE_RSA_TOKEN, new RsaVerifier(N, D));
		});
	}

	@Test
	public void rsaVerificationIsInverseOfSigning() {
		Jwt jwt = JwtHelper.encode(JOE_CLAIM_SEGMENT, new RsaSigner(N, E));
		jwt.verifySignature(new RsaVerifier(N, D));
	}
}
