package org.springframework.security.oauth2.provider.token.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Dave Syer
 *
 */
public class JwtTokenStoreTests {

	
	private JwtAccessTokenConverter enhancer = new JwtAccessTokenConverter();

	private JwtTokenStore tokenStore = new JwtTokenStore(enhancer);

	private InMemoryApprovalStore approvalStore = new InMemoryApprovalStore();

	private OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request(
			Collections.singletonMap("grant_type", "password"), "id", null, true, Collections.singleton("read"), null,
			null, null, null);

	private OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
			new TestAuthentication("test", true));

	private OAuth2AccessToken expectedOAuth2AccessToken;

	private OAuth2AccessToken expectedOAuth2RefreshToken;

	@BeforeEach
	public void init() throws Exception {
		enhancer.afterPropertiesSet();
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("testToken");
		original.setScope(expectedAuthentication.getOAuth2Request().getScope());
		expectedOAuth2AccessToken = enhancer.enhance(original, expectedAuthentication);
		convertToRefreshToken(original);
		expectedOAuth2RefreshToken = enhancer.enhance(original, expectedAuthentication);
	}

	protected void convertToRefreshToken(DefaultOAuth2AccessToken original) {
		Map<String, Object> map = new HashMap<String, Object>(original.getAdditionalInformation());
		map.put(AccessTokenConverter.ATI, "FOO");
		original.setAdditionalInformation(map);
	}

	@Test
	public void testAccessTokenCannotBeExtractedFromAuthentication() throws Exception {
		OAuth2AccessToken accessToken = tokenStore.getAccessToken(expectedAuthentication);
		assertNull(accessToken);
	}

	@Test
	public void testReadAccessToken() throws Exception {
		assertEquals(expectedOAuth2AccessToken, tokenStore.readAccessToken(expectedOAuth2AccessToken.getValue()));
	}

	@Test
	public void testNonAccessTokenNotReadable() throws Exception {
		assertThrows(InvalidTokenException.class, () -> {
			assertNull(tokenStore.readAccessToken("FOO"));
		});
	}

	@Test
	public void testNonRefreshTokenNotReadable() throws Exception {
		assertThrows(InvalidTokenException.class, () -> {
			assertNull(tokenStore.readRefreshToken("FOO"));
		});
	}

	@Test
	public void testAccessTokenIsNotARefreshToken() throws Exception {
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setExpiration(new Date());
		DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) enhancer.enhance(original, expectedAuthentication);
		assertThatThrownBy(() -> tokenStore.readRefreshToken(token.getValue()))
				.isInstanceOf(InvalidTokenException.class);
	}

	@Test
	public void testRefreshTokenIsNotAnAccessToken() throws Exception {
		assertThatThrownBy(() -> tokenStore.readAccessToken(expectedOAuth2RefreshToken.getValue()))
				.isInstanceOf(InvalidTokenException.class);
	}

	@Test
	public void testReadAccessTokenWithLongExpiration() throws Exception {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(expectedOAuth2AccessToken);
		token.setExpiration(new Date(Long.MAX_VALUE - 1));
		expectedOAuth2AccessToken = enhancer.enhance(token, expectedAuthentication);
		assertEquals(expectedOAuth2AccessToken, tokenStore.readAccessToken(expectedOAuth2AccessToken.getValue()));
	}

	@Test
	public void testReadRefreshToken() throws Exception {
		assertEquals(expectedOAuth2RefreshToken, tokenStore.readRefreshToken(expectedOAuth2RefreshToken.getValue()));
	}

	@Test
	public void testReadNonExpiringRefreshToken() throws Exception {
		assertFalse(tokenStore.readRefreshToken(expectedOAuth2RefreshToken.getValue()) instanceof DefaultExpiringOAuth2RefreshToken);
	}

	@Test
	public void testReadExpiringRefreshToken() throws Exception {
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setExpiration(new Date());
		convertToRefreshToken(original);
		DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) enhancer.enhance(original, expectedAuthentication);
		assertTrue(tokenStore.readRefreshToken(token.getValue()) instanceof DefaultExpiringOAuth2RefreshToken);
	}

	@Test
	public void testReadAuthentication() throws Exception {
		checkAuthentications(expectedAuthentication, tokenStore.readAuthentication(expectedOAuth2AccessToken));
	}

	@Test
	public void testReadAuthenticationFromString() throws Exception {
		checkAuthentications(expectedAuthentication,
				tokenStore.readAuthentication(expectedOAuth2AccessToken.getValue()));
	}

	@Test
	public void testAuthenticationPreservesGrantType() throws Exception {
		DefaultAccessTokenConverter delegate = new DefaultAccessTokenConverter();
		delegate.setIncludeGrantType(true);
		enhancer.setAccessTokenConverter(delegate);
		expectedOAuth2AccessToken = enhancer.enhance(new DefaultOAuth2AccessToken("FOO"), expectedAuthentication);
		OAuth2Authentication authentication = tokenStore.readAuthentication(expectedOAuth2AccessToken.getValue());
		assertEquals("password", authentication.getOAuth2Request().getGrantType());
	}

	@Test
	public void testReadAuthenticationForRefreshToken() throws Exception {
		checkAuthentications(expectedAuthentication,
				tokenStore.readAuthenticationForRefreshToken(new DefaultOAuth2RefreshToken(expectedOAuth2AccessToken
						.getValue())));
	}

	@Test
	public void removeAccessToken() throws Exception {
		tokenStore.setApprovalStore(approvalStore);
		approvalStore.addApprovals(Collections.singleton(new Approval("test", "id", "read", new Date(),
				ApprovalStatus.APPROVED)));
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
		tokenStore.removeAccessToken(expectedOAuth2AccessToken);
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
	}

	@Test
	public void removeRefreshToken() throws Exception {
		tokenStore.setApprovalStore(approvalStore);
		approvalStore.addApprovals(Collections.singleton(new Approval("test", "id", "read", new Date(),
				ApprovalStatus.APPROVED)));
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
		tokenStore.removeRefreshToken(new DefaultOAuth2RefreshToken(expectedOAuth2AccessToken.getValue()));
		assertEquals(0, approvalStore.getApprovals("test", "id").size());
	}

	@Test
	public void removeAccessTokenFromRefreshToken() throws Exception {
		tokenStore.setApprovalStore(approvalStore);
		approvalStore.addApprovals(Collections.singleton(new Approval("test", "id", "read", new Date(),
				ApprovalStatus.APPROVED)));
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
		tokenStore.removeAccessTokenUsingRefreshToken(new DefaultOAuth2RefreshToken(expectedOAuth2AccessToken
				.getValue()));
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
	}

	@Test
	public void testReadRefreshTokenForUnapprovedScope() throws Exception {
		tokenStore.setApprovalStore(approvalStore);
		approvalStore.addApprovals(Collections.singleton(new Approval("test", "id", "write", new Date(),
				ApprovalStatus.APPROVED)));
		assertEquals(1, approvalStore.getApprovals("test", "id").size());
		assertNull(tokenStore.readRefreshToken(expectedOAuth2RefreshToken.getValue()));
	}

	private void checkAuthentications(OAuth2Authentication expected, OAuth2Authentication actual) {
		assertEquals(expected.getOAuth2Request().getScope(), actual.getOAuth2Request().getScope());
		assertEquals(expected.getOAuth2Request().getClientId(), actual.getOAuth2Request().getClientId());
		assertEquals(expected.getUserAuthentication(), actual.getUserAuthentication());
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return "N/A";
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
