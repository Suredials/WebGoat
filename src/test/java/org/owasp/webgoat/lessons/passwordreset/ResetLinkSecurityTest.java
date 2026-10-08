/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.web.client.RestTemplate;
import org.springframework.validation.BindingResult;

class ResetLinkSecurityTest {
  @Test
  void resetLinkCannotBeRequestedForAnotherUser() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword endpoint =
        new ResetLinkAssignmentForgotPassword(restTemplate, "http://localhost:9090/mail");

    assertThat(endpoint.sendPasswordResetLink(ResetLinkAssignment.TOM_EMAIL, "webgoat").isLessonCompleted())
        .isFalse();
    verifyNoInteractions(restTemplate);
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
