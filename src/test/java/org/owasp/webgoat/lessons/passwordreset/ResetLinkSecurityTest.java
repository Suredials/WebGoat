/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.http.HttpMethod;
import org.springframework.validation.BindingResult;
import org.springframework.web.client.RestTemplate;

class ResetLinkSecurityTest {
  @Test
  void resetLinkCanOnlyBeRedeemedByTheEmailOwner() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword endpoint =
        new ResetLinkAssignmentForgotPassword(
            restTemplate,
            "http://127.0.0.1:9090/WebWolf",
            "http://127.0.0.1:9090/WebWolf/mail");
    endpoint.sendPasswordResetLink(ResetLinkAssignment.TOM_EMAIL);
    ArgumentCaptor<String> callbackUrl = ArgumentCaptor.forClass(String.class);
    verify(restTemplate)
        .exchange(callbackUrl.capture(), org.mockito.ArgumentMatchers.eq(HttpMethod.GET),
            org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq(Void.class));

    Matcher linkMatcher = Pattern.compile("reset-password/([0-9a-f-]{36})")
        .matcher(callbackUrl.getValue());
    assertThat(linkMatcher.find()).isTrue();
    String resetLink = linkMatcher.group(1);

    ResetLinkAssignment assignment = new ResetLinkAssignment();
    PasswordChangeForm form = new PasswordChangeForm();
    form.setResetLink(resetLink);
    form.setPassword("new-secret");
    BindingResult binding = mock(BindingResult.class);

    assertThat(assignment.changePassword(form, binding, "webgoat").getViewName())
        .endsWith("password_link_not_found.html");
    assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("webgoat");
    assertThat(assignment.changePassword(form, binding, "tom").getViewName())
        .endsWith("success.html");
    assertThat(assignment.login("new-secret", ResetLinkAssignment.TOM_EMAIL, "tom")
            .isLessonCompleted())
        .isTrue();
    ResetLinkAssignment.usersToTomPassword.remove("tom");
  }

  @Test
  void resetTokenIsBoundToOwnerAndConsumedOnce() {
    ResetLinkAssignment assignment = new ResetLinkAssignment();
    String owner = UUID.randomUUID().toString();
    String token = UUID.randomUUID().toString();
    ResetLinkAssignment.registerResetLink(token, owner, ResetLinkAssignment.TOM_EMAIL);
    PasswordChangeForm form = new PasswordChangeForm();
    form.setResetLink(token);
    form.setPassword("new-secret");
    BindingResult binding = mock(BindingResult.class);

    assertThat(assignment.changePassword(form, binding, "other-user").getViewName())
        .endsWith("password_link_not_found.html");
    assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey(owner);
    assertThat(assignment.changePassword(form, binding, owner).getViewName())
        .endsWith("success.html");
    assertThat(ResetLinkAssignment.usersToTomPassword.get(owner)).isEqualTo("new-secret");
    assertThat(assignment.changePassword(form, binding, owner).getViewName())
        .endsWith("password_link_not_found.html");
    ResetLinkAssignment.usersToTomPassword.remove(owner);
  }
}
