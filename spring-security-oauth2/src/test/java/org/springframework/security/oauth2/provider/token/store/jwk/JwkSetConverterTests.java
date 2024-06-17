/*
 * Copyright 2012-2019 the original author or authors.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.KEYS;

/**
 * Tests for {@link JwkSetConverter}.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 */
public class JwkSetConverterTests {
    private final JwkSetConverter converter = new JwkSetConverter();
    private final ObjectMapper objectMapper = new ObjectMapper();


    @Test
    public void convertWhenJwkSetStreamIsNullThenThrowJwkException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert(null))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object.");
    }

    @Test
    public void convertWhenJwkSetStreamIsEmptyThenThrowJwkException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert(new ByteArrayInputStream(new byte[0])))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object.");
    }

    @Test
    public void convertWhenJwkSetStreamNotAnObjectThenThrowJwkException() throws Exception {
        assertThatThrownBy(() -> this.converter.convert(new ByteArrayInputStream("".getBytes())))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object.");
    }

    @Test
    public void convertWhenJwkSetStreamHasMissingKeysAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<>();
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object.");
    }

    @Test
    public void convertWhenJwkSetStreamHasInvalidKeysAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        jwkSetObject.put(KEYS + "-invalid", new Map[0]);
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object.");
    }

    @Test
    public void convertWhenJwkSetStreamHasInvalidJwkElementsThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        jwkSetObject.put(JwkAttributes.KEYS, "");
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Invalid JWK Set Object. The JWK Set MUST have an array of JWK(s).");
    }

    @Test
    public void convertWhenJwkSetStreamHasEmptyJwkElementsThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        jwkSetObject.put(JwkAttributes.KEYS, new Map[0]);
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    @Test
    public void convertWhenJwkSetStreamHasEmptyJwkElementThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = new HashMap<String, Object>();
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    @Test
    public void convertWhenJwkSetStreamHasJwkElementWithOCTKeyTypeThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.OCT);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    @Test
    public void convertWhenJwkSetStreamHasRSAJwkElementWithMissingKeyIdAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, null, JwkDefinition.PublicKeyUse.SIG);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "kid is a required attribute for a JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasRSAJwkElementWithENCPublicKeyUseAttributeThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1", JwkDefinition.PublicKeyUse.ENC);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    // gh-1871
    @Test
    public void convertWhenJwkSetStreamHasRSAJwkElementWithoutPublicKeyUseAttributeThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    @Test
    public void convertWhenJwkSetStreamHasRSAJwkElementWithMissingModulusAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.RS256);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});

        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "n is a required attribute for a RSA JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasRSAJwkElementWithMissingExponentAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.RS256, "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "e is a required attribute for a RSA JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithMissingKeyIdAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject(null, JwkDefinition.PublicKeyUse.SIG, null);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "kid is a required attribute for an EC JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithENCPublicKeyUseAttributeThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject("key-id-1", JwkDefinition.PublicKeyUse.ENC, null);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    // gh-1871
    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithoutPublicKeyUseAttributeThenReturnEmptyJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject("key-id-1", null, null);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertTrue(jwkSet.isEmpty(), "JWK Set NOT empty");
    }

    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithMissingXAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject("key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.ES256);
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "x is a required attribute for an EC JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithMissingYAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject("key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.ES256,
                "IsxeG33-QlL2u-O38QKwAbw5tJTZ-jtMVSlzjNXhvys");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "y is a required attribute for an EC JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamHasECJwkElementWithMissingCurveAttributeThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createEllipticCurveJwkObject("key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.ES256,
                "IsxeG33-QlL2u-O38QKwAbw5tJTZ-jtMVSlzjNXhvys", "FPTFJF1M0sNRlOVZIH4e1DoZ_hdg1OvF6BlP2QHmSCg");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "crv is a required attribute for an EC JWK.");
    }

    @Test
    public void convertWhenJwkSetStreamIsValidThenReturnJwkSet() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.RS256, "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL", "AQAB");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject});
        Set<JwkDefinition> jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertNotNull(jwkSet);
        assertEquals(1, jwkSet.size(), "JWK Set NOT size=1");

        Map<String, Object> jwkObject2 = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-2",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.RS512,
                "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL", "AQAB", new String[]{"chain1", "chain2"});
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject, jwkObject2});
        jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertNotNull(jwkSet);
        assertEquals(2, jwkSet.size(), "JWK Set NOT size=2");

        Map<String, Object> jwkObject3 = this.createEllipticCurveJwkObject("key-id-3",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.ES256,
                "IsxeG33-QlL2u-O38QKwAbw5tJTZ-jtMVSlzjNXhvys", "FPTFJF1M0sNRlOVZIH4e1DoZ_hdg1OvF6BlP2QHmSCg", "P-256");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject, jwkObject2, jwkObject3});
        jwkSet = this.converter.convert(this.asInputStream(jwkSetObject));
        assertNotNull(jwkSet);
        assertEquals(3, jwkSet.size(), "JWK Set NOT size=3");
    }

    @Test
    public void convertWhenJwkSetStreamHasDuplicateJwkElementsThenThrowJwkException() throws Exception {
        Map<String, Object> jwkSetObject = new HashMap<String, Object>();
        Map<String, Object> jwkObject = this.createJwkObject(JwkDefinition.KeyType.RSA, "key-id-1",
                JwkDefinition.PublicKeyUse.SIG, JwkDefinition.CryptoAlgorithm.RS256, "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL", "AQAB");
        jwkSetObject.put(JwkAttributes.KEYS, new Map[]{jwkObject, jwkObject});
        assertThatThrownBy(() -> this.converter.convert(this.asInputStream(jwkSetObject)))
                .isInstanceOf(JwkException.class)
                .withFailMessage(() -> "Duplicate JWK found in Set: key-id-1 (kid)");
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType) {
        return this.createJwkObject(keyType, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType, String keyId) {
        return this.createJwkObject(keyType, keyId, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType,
                                                String keyId,
                                                JwkDefinition.PublicKeyUse publicKeyUse) {

        return this.createJwkObject(keyType, keyId, publicKeyUse, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType,
                                                String keyId,
                                                JwkDefinition.PublicKeyUse publicKeyUse,
                                                JwkDefinition.CryptoAlgorithm algorithm) {

        return this.createJwkObject(keyType, keyId, publicKeyUse, algorithm, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType,
                                                String keyId,
                                                JwkDefinition.PublicKeyUse publicKeyUse,
                                                JwkDefinition.CryptoAlgorithm algorithm,
                                                String rsaModulus) {

        return this.createJwkObject(keyType, keyId, publicKeyUse, algorithm, rsaModulus, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType,
                                                String keyId,
                                                JwkDefinition.PublicKeyUse publicKeyUse,
                                                JwkDefinition.CryptoAlgorithm algorithm,
                                                String rsaModulus,
                                                String rsaExponent) {

        return this.createJwkObject(keyType, keyId, publicKeyUse, algorithm, rsaModulus, rsaExponent, null);
    }

    private Map<String, Object> createJwkObject(JwkDefinition.KeyType keyType,
                                                String keyId,
                                                JwkDefinition.PublicKeyUse publicKeyUse,
                                                JwkDefinition.CryptoAlgorithm algorithm,
                                                String rsaModulus,
                                                String rsaExponent,
                                                String[] x5c) {

        Map<String, Object> jwkObject = new HashMap<String, Object>();
        jwkObject.put(JwkAttributes.KEY_TYPE, keyType.value());
        if (keyId != null) {
            jwkObject.put(JwkAttributes.KEY_ID, keyId);
        }
        if (publicKeyUse != null) {
            jwkObject.put(JwkAttributes.PUBLIC_KEY_USE, publicKeyUse.value());
        }
        if (algorithm != null) {
            jwkObject.put(JwkAttributes.ALGORITHM, algorithm.headerParamValue());
        }
        if (rsaModulus != null) {
            jwkObject.put(JwkAttributes.RSA_PUBLIC_KEY_MODULUS, rsaModulus);
        }
        if (rsaExponent != null) {
            jwkObject.put(JwkAttributes.RSA_PUBLIC_KEY_EXPONENT, rsaExponent);
        }
        // gh-1082 - parser should be able to handle arrays
        if (x5c != null) {
            // x5c (X.509 certificate chain)
            jwkObject.put("x5c", x5c);
        }
        return jwkObject;
    }

    private Map<String, Object> createEllipticCurveJwkObject(String keyId,
                                                             JwkDefinition.PublicKeyUse publicKeyUse,
                                                             JwkDefinition.CryptoAlgorithm algorithm) {
        return this.createEllipticCurveJwkObject(keyId, publicKeyUse, algorithm, null, null, null);
    }

    private Map<String, Object> createEllipticCurveJwkObject(String keyId,
                                                             JwkDefinition.PublicKeyUse publicKeyUse,
                                                             JwkDefinition.CryptoAlgorithm algorithm,
                                                             String x) {
        return this.createEllipticCurveJwkObject(keyId, publicKeyUse, algorithm, x, null, null);
    }

    private Map<String, Object> createEllipticCurveJwkObject(String keyId,
                                                             JwkDefinition.PublicKeyUse publicKeyUse,
                                                             JwkDefinition.CryptoAlgorithm algorithm,
                                                             String x,
                                                             String y) {
        return this.createEllipticCurveJwkObject(keyId, publicKeyUse, algorithm, x, y, null);
    }

    private Map<String, Object> createEllipticCurveJwkObject(String keyId,
                                                             JwkDefinition.PublicKeyUse publicKeyUse,
                                                             JwkDefinition.CryptoAlgorithm algorithm,
                                                             String x,
                                                             String y,
                                                             String curve) {

        Map<String, Object> jwkObject = new HashMap<String, Object>();
        jwkObject.put(JwkAttributes.KEY_TYPE, JwkDefinition.KeyType.EC);
        if (keyId != null) {
            jwkObject.put(JwkAttributes.KEY_ID, keyId);
        }
        if (publicKeyUse != null) {
            jwkObject.put(JwkAttributes.PUBLIC_KEY_USE, publicKeyUse.value());
        }
        if (algorithm != null) {
            jwkObject.put(JwkAttributes.ALGORITHM, algorithm.headerParamValue());
        }
        if (x != null) {
            jwkObject.put(JwkAttributes.EC_PUBLIC_KEY_X, x);
        }
        if (y != null) {
            jwkObject.put(JwkAttributes.EC_PUBLIC_KEY_Y, y);
        }
        if (curve != null) {
            jwkObject.put(JwkAttributes.EC_PUBLIC_KEY_CURVE, curve);
        }
        return jwkObject;
    }

    private InputStream asInputStream(Map<String, Object> content) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        this.objectMapper.writeValue(out, content);
        return new ByteArrayInputStream(out.toByteArray());
    }
}
