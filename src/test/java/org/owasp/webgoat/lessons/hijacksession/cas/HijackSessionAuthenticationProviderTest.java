/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication.AuthenticationBuilder;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class HijackSessionAuthenticationProviderTest {

  HijackSessionAuthenticationProvider provider = new HijackSessionAuthenticationProvider();

  @ParameterizedTest
  @DisplayName("Provider authentication test")
  @MethodSource("authenticationForCookieValues")
  void testProviderAuthenticationGeneratesCookie(Authentication authentication) {
    Authentication auth = provider.authenticate(authentication);
    assertThat(auth.getId(), not(StringUtils.isEmpty(auth.getId())));
  }

  @Test
  void generatedSessionIdsIncludeAnUnpredictableSuffix() {
    String firstId = provider.authenticate(null).getId();
    String secondId = provider.authenticate(null).getId();
    String uuidSuffix = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

    assertThat(firstId.matches("\\d+-\\d+-" + uuidSuffix), is(true));
    assertThat(secondId.matches("\\d+-\\d+-" + uuidSuffix), is(true));
    assertThat(firstId, not(is(secondId)));
  }

  @Test
  void testAuthenticated() {
    String id = "anyId";
    provider.addSession(id);

    Authentication auth = provider.authenticate(Authentication.builder().id(id).build());

    assertThat(auth.getId(), is(id));
    assertThat(auth.isAuthenticated(), is(true));

    auth = provider.authenticate(Authentication.builder().id("otherId").build());

    assertThat(auth.getId(), is("otherId"));
    assertThat(auth.isAuthenticated(), is(false));
  }

  @Test
  void testAuthenticationToString() {
    AuthenticationBuilder authBuilder =
        Authentication.builder()
            .name("expectedName")
            .credentials("expectedCredentials")
            .id("expectedId");

    Authentication auth = authBuilder.build();

    String expected =
        "Authentication.AuthenticationBuilder("
            + "name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(authBuilder.toString(), is(expected));

    expected =
        "Authentication(authenticated="
            + auth.isAuthenticated()
            + ", name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(auth.toString(), is(expected));
  }

  @Test
  void testMaxSessions() {
    for (int i = 0; i <= HijackSessionAuthenticationProvider.MAX_SESSIONS + 1; i++) {
      provider.authorizedUserAutoLogin();
      provider.addSession(null);
    }

    assertThat(provider.getSessionsSize(), is(HijackSessionAuthenticationProvider.MAX_SESSIONS));
  }

  private static Stream<Arguments> authenticationForCookieValues() {
    return Stream.of(
        Arguments.of((Object) null),
        Arguments.of(Authentication.builder().name("any").credentials("any").build()),
        Arguments.of(Authentication.builder().id("any").build()));
  }
}
