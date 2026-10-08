/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webWolfURL;
  private final String webWolfMailURL;

  @Value("${webgoat.url}")
  private String trustedResetBaseUrl;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    if (email == null || !email.matches("[^@\\s]+@[^@\\s]+")) {
      return failed(this).build();
    }
    String requestedUsername = email.substring(0, email.indexOf('@'));

    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.registerResetLink(resetLink, requestedUsername, email);

    if (ResetLinkAssignment.TOM_EMAIL.equalsIgnoreCase(email)) {
      simulateRecipientClick(resetLink);
      return failed(this).feedback("email.send").feedbackArgs(email).build();
    }

    try {
      sendMailToUser(email, trustedResetBaseUrl, resetLink);
    } catch (Exception e) {
      ResetLinkAssignment.revokeResetLink(resetLink);
      return failed(this).output("Unable to send reset email").build();
    }

    return failed(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void simulateRecipientClick(String resetLink) {
    try {
      restTemplate.exchange(
          "%s/PasswordReset/reset/reset-password/%s".formatted(webWolfURL, resetLink),
          HttpMethod.GET,
          null,
          Void.class);
    } catch (Exception ignored) {
      // The simulated recipient click is best-effort and must not invalidate the reset request.
    }
  }

}
