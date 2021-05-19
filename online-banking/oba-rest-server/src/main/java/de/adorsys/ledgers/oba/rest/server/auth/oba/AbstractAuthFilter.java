package de.adorsys.ledgers.oba.rest.server.auth.oba;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.util.DateUtils;
import de.adorsys.ledgers.middleware.api.domain.um.AccessTokenTO;
import de.adorsys.ledgers.middleware.api.domain.um.BearerTokenTO;
import de.adorsys.ledgers.oba.rest.server.auth.ObaMiddlewareAuthentication;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static de.adorsys.ledgers.oba.rest.server.auth.oba.SecurityConstant.ACCESS_TOKEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
public abstract class AbstractAuthFilter extends OncePerRequestFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();

    protected void handleAuthenticationFailure(HttpServletResponse response, Exception e) throws IOException {
        log.error(e.getMessage());
        doAuthenticationFailure(response, UNAUTHORIZED.getReasonPhrase());
    }

    private void doAuthenticationFailure(HttpServletResponse response, String message) throws IOException {

        Map<String, String> data = new ErrorResponse()
                                       .buildContent(UNAUTHORIZED.value(), message);

        response.setStatus(UNAUTHORIZED.value());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getOutputStream().println(objectMapper.writeValueAsString(data));
    }

    protected String obtainFromHeader(HttpServletRequest request, String headerKey) {
        return request.getHeader(headerKey);
    }

    protected boolean authenticationIsRequired() {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

        return isNotAuthenticated(existingAuth) || isNotMiddlewareAuthentication(existingAuth);
    }

    protected void fillSecurityContext(BearerTokenTO token) {
        SecurityContextHolder.getContext()
            .setAuthentication(new ObaMiddlewareAuthentication(token.getAccessTokenObject(), token, buildGrantedAuthorities(token.getAccessTokenObject())));
    }

    private boolean isNotAuthenticated(Authentication existingAuth) {
        return existingAuth == null || !existingAuth.isAuthenticated();
    }

    private boolean isNotMiddlewareAuthentication(Authentication existingAuth) {
        return !(existingAuth instanceof ObaMiddlewareAuthentication);
    }

    private List<GrantedAuthority> buildGrantedAuthorities(AccessTokenTO accessTokenTO) {
        return accessTokenTO.getRole() != null
            ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + accessTokenTO.getRole().name()))
            : Collections.emptyList();
    }


    protected void removeCookie(HttpServletResponse response, String cookieName, boolean isSecure) {
        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(isSecure);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    protected void addRefreshTokenCookie(HttpServletResponse response, String jwtId, String refreshToken, boolean isSecure) {
        String cookieName = SecurityConstant.REFRESH_TOKEN_COOKIE_PREFIX + jwtId;
        Cookie cookie = new Cookie(cookieName, refreshToken);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(expiredTimeInSec(refreshToken).intValue());
        cookie.setSecure(isSecure);
        cookie.setPath("/");
        response.addCookie(cookie);
    }


    protected void refreshUserSession(BearerTokenTO bearerTokenTO, HttpServletResponse response, boolean isSecure) {
        String access_token = bearerTokenTO.getAccess_token();
        addRefreshTokenCookie(response, jwtId(access_token), bearerTokenTO.getRefresh_token(), isSecure);
        addBearerTokenHeader(access_token, response);
    }

    protected void addBearerTokenHeader(String token, HttpServletResponse response) {
        response.setHeader(ACCESS_TOKEN, token);
    }

    protected String resolveBearerToken(HttpServletRequest request) {
        return Optional.ofNullable(obtainFromHeader(request, HttpHeaders.AUTHORIZATION))
            .filter(StringUtils::isNotBlank)
            .filter(t -> StringUtils.startsWithIgnoreCase(t, SecurityConstant.BEARER_TOKEN_PREFIX))
            .map(t -> StringUtils.substringAfter(t, SecurityConstant.BEARER_TOKEN_PREFIX))
            .orElse(null);
    }

    @SneakyThrows
    protected String jwtId(String jwtToken) {
        return JWTParser.parse(jwtToken).getJWTClaimsSet().getJWTID();
    }

    @SneakyThrows
    protected boolean isExpiredToken(String jwtToken) {
        Date expirationTime = JWTParser.parse(jwtToken).getJWTClaimsSet().getExpirationTime();
        return Optional.ofNullable(expirationTime)
            .map(d -> d.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
            .map(d -> d.isBefore(LocalDateTime.now()))
            .orElse(true);
    }

    @SneakyThrows
    protected Long expiredTimeInSec(String jwtToken) {
        Date issueTime = JWTParser.parse(jwtToken).getJWTClaimsSet().getIssueTime();
        Date expirationTime = JWTParser.parse(jwtToken).getJWTClaimsSet().getExpirationTime();
        return DateUtils.toSecondsSinceEpoch(expirationTime) - DateUtils.toSecondsSinceEpoch(issueTime);
    }

}
