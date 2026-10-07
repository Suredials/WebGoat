/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

final class TokenSigningKeys {
  private TokenSigningKeys() {}

  static String generate() {
    byte[] key = new byte[64];
    new java.security.SecureRandom().nextBytes(key);
    return java.util.Base64.getEncoder().encodeToString(key);
  }
}
