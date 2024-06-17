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

package org.springframework.security.oauth2.client.http;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResponseErrorHandler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2ErrorHandlerTests {

    @Mock
    private ClientHttpResponse response;

    private BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();

    private final class TestClientHttpResponse implements ClientHttpResponse {

        private final HttpHeaders headers;

        private final HttpStatus status;

        private final InputStream body;

        public TestClientHttpResponse(HttpHeaders headers, int status) {
            this(headers, status, new ByteArrayInputStream(new byte[0]));
        }

        public TestClientHttpResponse(HttpHeaders headers, int status, InputStream bodyStream) {
            this.headers = headers;
            this.status = HttpStatus.valueOf(status);
            this.body = bodyStream;
        }

        public InputStream getBody() throws IOException {
            return body;
        }

        public HttpHeaders getHeaders() {
            return headers;
        }

        public HttpStatus getStatusCode() throws IOException {
            return status;
        }

        public String getStatusText() throws IOException {
            return status.getReasonPhrase();
        }

        public int getRawStatusCode() throws IOException {
            return status.value();
        }

        public void close() {
        }
    }

    private OAuth2ErrorHandler handler;

    @BeforeEach
    public void setUp() throws Exception {
        handler = new OAuth2ErrorHandler(resource);

    }

    /**
     * test response with www-authenticate header
     */
    @Test
    public void testHandleErrorClientHttpResponse() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.set("www-authenticate", "Bearer error=foo");
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

        // We lose the www-authenticate content in a nested exception (but it's still available) through the
        // HttpClientErrorException

        assertThatThrownBy(() -> handler.handleError(response))
                .withFailMessage("401 Unauthorized");

    }

    @Test
    public void testHandleErrorWithInvalidToken() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.set("www-authenticate", "Bearer error=\"invalid_token\", description=\"foo\"");
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(AccessTokenRequiredException.class)
                .withFailMessage("OAuth2 access denied");

    }

    @Test
    public void testCustomHandler() throws Exception {

        OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {

            public boolean hasError(ClientHttpResponse response) throws IOException {
                return true;
            }

            public void handleError(ClientHttpResponse response) throws IOException {
                throw new RuntimeException("planned");
            }
        }, resource);

        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);

        assertThatThrownBy(() -> handler.handleError(response))
                .withFailMessage("planned");

    }

    @Test
    public void testHandle500Error() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 500);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpServerErrorException.class);
    }

    @Test
    public void testHandleGeneric400Error() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    public void testHandleGeneric403Error() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    // See https://github.com/spring-projects/spring-security-oauth/issues/387
    public void testHandleGeneric403ErrorWithBody() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403,
                new ByteArrayInputStream("{}".getBytes()));
        handler = new OAuth2ErrorHandler(new DefaultResponseErrorHandler(), resource);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpClientErrorException.class);
    }

    @Test
    public void testBodyCanBeUsedByCustomHandler() throws Exception {
        final String appSpecificBodyContent = "{\"some_status\":\"app error\"}";
        OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return true;
            }

            public void handleError(ClientHttpResponse response) throws IOException {
                InputStream body = response.getBody();
                byte[] buf = new byte[appSpecificBodyContent.length()];
                int readResponse = body.read(buf);
                assertEquals(buf.length, readResponse);
                assertEquals(appSpecificBodyContent, new String(buf, "UTF-8"));
                throw new RuntimeException("planned");
            }
        }, resource);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Length", "" + appSpecificBodyContent.length());
        headers.set("Content-Type", "application/json");
        InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400, appSpecificErrorBody);

        assertThatThrownBy(() -> handler.handleError(response))
                .withFailMessage("planned");
    }

    @Test
    public void testHandleErrorWithMissingHeader() throws IOException {

        final HttpHeaders headers = new HttpHeaders();
        when(response.getHeaders()).thenReturn(headers);
        when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);
        when(response.getBody()).thenReturn(new ByteArrayInputStream(new byte[0]));
        when(response.getStatusText()).thenReturn(HttpStatus.BAD_REQUEST.toString());

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpClientErrorException.class);
    }

    // gh-875
    @Test
    public void testHandleErrorWhenAccessDeniedMessageAndStatus400ThenThrowsUserDeniedAuthorizationException() throws Exception {
        String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
        ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400, messageBody);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(UserDeniedAuthorizationException.class);
    }

    // gh-875
    @Test
    public void testHandleErrorWhenAccessDeniedMessageAndStatus403ThenThrowsOAuth2AccessDeniedException() throws Exception {
        String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
        ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403, messageBody);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(OAuth2AccessDeniedException.class);
    }

    @Test
    public void testHandleMessageConversionExceptions() throws Exception {
        HttpMessageConverter<?> extractor = new HttpMessageConverter() {
            @Override
            public boolean canRead(Class clazz, MediaType mediaType) {
                return true;
            }

            @Override
            public boolean canWrite(Class clazz, MediaType mediaType) {
                return false;
            }

            @Override
            public List<MediaType> getSupportedMediaTypes() {
                return null;
            }

            @Override
            public Object read(Class clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
                throw new HttpMessageConversionException("error");
            }

            @Override
            public void write(Object o, MediaType contentType, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {

            }
        };

        ArrayList<HttpMessageConverter<?>> messageConverters = new ArrayList<HttpMessageConverter<?>>();
        messageConverters.add(extractor);
        handler.setMessageConverters(messageConverters);

        HttpHeaders headers = new HttpHeaders();
        final String appSpecificBodyContent = "This user is not authorized";
        InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401, appSpecificErrorBody);

        assertThatThrownBy(() -> handler.handleError(response))
                .isInstanceOf(HttpClientErrorException.class);
    }
}
