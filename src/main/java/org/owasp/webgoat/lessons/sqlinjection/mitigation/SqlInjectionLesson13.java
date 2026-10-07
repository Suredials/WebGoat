/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-13-1",
      "SqlStringInjectionHint-mitigation-13-2",
      "SqlStringInjectionHint-mitigation-13-3",
      "SqlStringInjectionHint-mitigation-13-4"
    })
public class SqlInjectionLesson13 implements AssignmentEndpoint {

  @PostMapping("/SqlInjectionMitigations/attack12a")
  @ResponseBody
  public AttackResult completed(@RequestParam String ip) {
    return failed(this).build();
  }
}
