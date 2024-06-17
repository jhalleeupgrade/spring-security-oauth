package org.springframework.security.oauth2.provider.expression;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;

/**
 * 
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2ExpressionParserTests {
	@Mock
	private ExpressionParser delegate;
	@Mock
	private ParserContext parserContext;

	private final String expressionString = "ORIGIONAL";

	private final String wrappedExpression = "#oauth2.throwOnError(" + expressionString + ")";

	private OAuth2ExpressionParser parser;
	
	@BeforeEach
	public void setUp() {
		parser = new OAuth2ExpressionParser(delegate);
	}

	@Test
	public void constructorNull() {
		assertThrows(IllegalArgumentException.class, () -> {
			new OAuth2ExpressionParser(null);
		});
	}
	
	@Test
	public void parseExpression() {
		parser.parseExpression(expressionString);
		verify(delegate).parseExpression(wrappedExpression);
	}
	
	@Test
	public void parseExpressionWithContext() {
		parser.parseExpression(expressionString, parserContext);
		verify(delegate).parseExpression(wrappedExpression, parserContext);
	}
}
