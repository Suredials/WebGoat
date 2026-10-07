/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

class TokenSecurityTest {
  @Test
  void refreshTokenCanBeUsedOnlyOnce() {
    JWTRefreshEndpoint endpoint = new JWTRefreshEndpoint();
    var login = endpoint.follow(java.util.Map.of("user", "Jerry", "password", JWTRefreshEndpoint.PASSWORD));
    java.util.Map<?, ?> tokens = (java.util.Map<?, ?>) login.getBody();
    String access = "Bearer " + tokens.get("access_token");
    var request = java.util.Map.<String, Object>of("refresh_token", tokens.get("refresh_token"));
    assertThat(endpoint.newToken(access, request).getStatusCode().value()).isEqualTo(200);
    assertThat(endpoint.newToken(access, request).getStatusCode().value()).isEqualTo(401);
  }

  @Test
  void votesAcceptValidAdminSignatureAndRejectUnsignedToken() {
    JWTVotesEndpoint endpoint = new JWTVotesEndpoint();
    Claims claims = Jwts.claims();
    claims.put("admin", "true");
    claims.put("user", "Tom");
    String signed = Jwts.builder().setClaims(claims)
        .signWith(SignatureAlgorithm.HS512, JWTVotesEndpoint.JWT_PASSWORD).compact();
    assertThat(endpoint.resetVotes(signed).isLessonCompleted()).isTrue();
    String unsigned = Jwts.builder().setClaims(claims).compact();
    assertThat(endpoint.resetVotes(unsigned).isLessonCompleted()).isFalse();
  }
}
