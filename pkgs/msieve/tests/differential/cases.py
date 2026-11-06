"""The differential cases: a script, a message (a key of MESSAGES), and optionally the envelope ("from", "to")."""

MESSAGES = {
    "plain": b"""From: Bob Smith <bob@bank.com>
To: User <user@example.com>, other@example.net
Cc: "Carol, C." <carol@Example.ORG>
Subject: Your monthly statement
Date: Tue, 3 Nov 2026 10:00:00 +0000
Message-ID: <abc@bank.com>
X-Spam-Flag: NO

Hello.
""",
    "encoded": b"""From: =?utf-8?q?J=C3=BCrgen?= <juergen@example.de>
To: user@example.com
Subject: =?utf-8?b?R3LDvMOfZSBhdXMgS8O2bG4=?=
X-Folded: first
  second

Body
""",
    "list": b"""From: list-owner@lists.example.org
To: dev@lists.example.org
Subject: [dev] Weekly digest
List-Id: <dev.lists.example.org>
Precedence: bulk
Received: from a by b; Tue, 3 Nov 2026 10:00:00 +0000
Received: from c by d; Tue, 3 Nov 2026 09:00:00 +0000

digest
""",
    "group": b"""From: alice@example.com
To: undisclosed-recipients:;
Cc: friends: dave@example.com, erin@Example.com;
Subject: party?

!
""",
    "big": b"""From: big@example.com
To: user@example.com
Subject: big

""" + b"x" * 5000 + b"\n",
    "odd": b"""From: weird
To: <@route,@other:user@example.com>
Subject: *star* and ?question? and back\\slash
X-Empty:
X-Spaces:    lots of   space

.
""",
}

CASES = [
    # Basics
    {"name": "empty", "script": ""},
    {"name": "keep", "script": "keep;"},
    {"name": "discard", "script": "discard;"},
    {"name": "stop", "script": "stop; discard;"},
    {"name": "comment", "script": "# a comment\n/* a\nblock */ discard;"},
    {"name": "keep-discard", "script": "keep; discard;"},
    {"name": "discard-keep", "script": "discard; keep;"},
    # fileinto
    {"name": "fileinto", "script": 'require "fileinto"; fileinto "Finance";'},
    {"name": "fileinto-twice", "script": 'require "fileinto"; fileinto "A"; fileinto "A";'},
    {"name": "fileinto-two", "script": 'require "fileinto"; fileinto "A"; fileinto "B";'},
    {"name": "fileinto-inbox", "script": 'require "fileinto"; fileinto "INBOX"; keep;'},
    {"name": "fileinto-norequire", "script": 'fileinto "A";'},
    {"name": "fileinto-copy", "script": 'require ["fileinto", "copy"]; fileinto :copy "A";'},
    {"name": "fileinto-copy-norequire", "script": 'require "fileinto"; fileinto :copy "A";'},
    {"name": "fileinto-utf8", "script": 'require "fileinto"; fileinto "Grüße";'},
    {"name": "fileinto-list", "script": 'require "fileinto"; fileinto ["A", "B"];'},
    # redirect
    {"name": "redirect", "script": 'redirect "boss@example.net";'},
    {"name": "redirect-copy", "script": 'require "copy"; redirect :copy "boss@example.net";'},
    {"name": "redirect-twice", "script": 'redirect "a@example.net"; redirect "a@example.net";'},
    {"name": "redirect-bad", "script": 'redirect "not an address";'},
    # header
    {"name": "header-is", "script": 'if header :is "subject" "Your monthly statement" { discard; }'},
    {"name": "header-is-case", "script": 'if header :is "Subject" "YOUR MONTHLY STATEMENT" { discard; }'},
    {"name": "header-is-octet", "script": 'require "comparator-i;octet"; if header :is :comparator "i;octet" "subject" "YOUR MONTHLY STATEMENT" { discard; }'},
    {"name": "header-contains", "script": 'if header :contains "subject" "monthly" { discard; }'},
    {"name": "header-contains-empty", "script": 'if header :contains "subject" "" { discard; }'},
    {"name": "header-contains-missing", "script": 'if header :contains "x-nothere" "" { discard; }'},
    {"name": "header-matches", "script": 'if header :matches "subject" "Your*statement" { discard; }'},
    {"name": "header-matches-q", "script": 'if header :matches "subject" "Your????????" { discard; }'},
    {"name": "header-matches-q2", "script": 'if header :matches "subject" "Your ???????*" { discard; }'},
    {"name": "header-matches-star", "script": 'if header :matches "subject" "*" { discard; }'},
    {"name": "header-matches-literal", "script": 'if header :matches "subject" "\\\\*star\\\\* and*" { discard; }', "message": "odd"},
    {"name": "header-matches-q-literal", "script": 'if header :matches "subject" "*\\\\?question\\\\?*" { discard; }', "message": "odd"},
    {"name": "header-list", "script": 'if header :contains ["to", "cc"] ["nobody", "carol"] { discard; }'},
    {"name": "header-encoded", "script": 'if header :contains "subject" "Köln" { discard; }', "message": "encoded"},
    {"name": "header-encoded-from", "script": 'if header :contains "from" "Jürgen" { discard; }', "message": "encoded"},
    {"name": "header-folded", "script": 'if header :is "x-folded" "first second" { discard; }', "message": "encoded"},
    {"name": "header-folded-contains", "script": 'if header :contains "x-folded" "first" { discard; }', "message": "encoded"},
    {"name": "header-multi", "script": 'if header :contains "received" "from c" { discard; }', "message": "list"},
    {"name": "header-empty-value", "script": 'if header :is "x-empty" "" { discard; }', "message": "odd"},
    {"name": "header-spaces", "script": 'if header :is "x-spaces" "lots of   space" { discard; }', "message": "odd"},
    {"name": "header-utf8-q", "script": 'if header :matches "subject" "Gr?ße*" { discard; }', "message": "encoded"},
    # address
    {"name": "address-all", "script": 'if address :is "from" "bob@bank.com" { discard; }'},
    {"name": "address-domain", "script": 'if address :domain :is "from" "bank.com" { discard; }'},
    {"name": "address-domain-case", "script": 'if address :domain :is "cc" "example.org" { discard; }'},
    {"name": "address-localpart", "script": 'if address :localpart :is "to" "other" { discard; }'},
    {"name": "address-contains", "script": 'if address :contains "to" "example.net" { discard; }'},
    {"name": "address-matches", "script": 'if address :matches "to" "*@example.*" { discard; }'},
    {"name": "address-display-no", "script": 'if address :contains "from" "Smith" { discard; }'},
    {"name": "address-group", "script": 'if address :is "cc" "erin@example.com" { discard; }', "message": "group"},
    {"name": "address-group-empty", "script": 'if address :contains "to" "undisclosed" { discard; }', "message": "group"},
    {"name": "address-noat", "script": 'if address :is "from" "weird" { discard; }', "message": "odd"},
    {"name": "address-route", "script": 'if address :is "to" "user@example.com" { discard; }', "message": "odd"},
    # envelope
    {"name": "envelope-from", "script": 'require "envelope"; if envelope :is "from" "sender@example.org" { discard; }'},
    {"name": "envelope-to", "script": 'require "envelope"; if envelope :domain :is "to" "example.com" { discard; }'},
    {"name": "envelope-localpart", "script": 'require "envelope"; if envelope :localpart :is "from" "sender" { discard; }'},
    {"name": "envelope-null", "script": 'require "envelope"; if envelope :is "from" "" { discard; }', "from": "", "expect": []},  # sieve-test refuses a null -f
    {"name": "envelope-norequire", "script": 'if envelope :is "from" "x" { discard; }'},
    # exists, size, true, false, not, anyof, allof
    {"name": "exists", "script": 'if exists "x-spam-flag" { discard; }'},
    {"name": "exists-all", "script": 'if exists ["from", "x-nothere"] { discard; }'},
    {"name": "size-over", "script": 'if size :over 1K { discard; }', "message": "big"},
    {"name": "size-under", "script": 'if size :under 1K { discard; }', "message": "big"},
    {"name": "size-under-plain", "script": 'if size :under 1K { discard; }'},
    {"name": "size-both", "script": 'if size :over :under 1K { discard; }'},
    {"name": "true", "script": 'if true { discard; }'},
    {"name": "false", "script": 'if false { discard; }'},
    {"name": "not", "script": 'if not false { discard; }'},
    {"name": "anyof", "script": 'if anyof (false, header :contains "subject" "monthly") { discard; }'},
    {"name": "allof", "script": 'if allof (true, header :contains "subject" "weekly") { discard; }'},
    {"name": "nested", "script": 'if allof (not anyof (false, false), true) { discard; }'},
    # if / elsif / else
    {"name": "elsif", "script": 'require "fileinto"; if false { fileinto "A"; } elsif true { fileinto "B"; } else { fileinto "C"; }'},
    {"name": "else", "script": 'require "fileinto"; if false { fileinto "A"; } elsif false { fileinto "B"; } else { fileinto "C"; }'},
    {"name": "if-if", "script": 'require "fileinto"; if true { fileinto "A"; } if true { fileinto "B"; }'},
    {"name": "else-alone", "script": 'else { discard; }'},
    {"name": "stop-in-if", "script": 'require "fileinto"; if true { fileinto "A"; stop; } fileinto "B";'},
    # imap4flags
    {"name": "flags-fileinto", "script": 'require ["fileinto", "imap4flags"]; fileinto :flags "\\\\Seen" "A";'},
    {"name": "flags-set", "script": 'require ["fileinto", "imap4flags"]; setflag "\\\\Flagged"; fileinto "A";'},
    {"name": "flags-add", "script": 'require ["imap4flags"]; addflag ["\\\\Seen", "custom"]; addflag "\\\\seen";'},
    {"name": "flags-remove", "script": 'require ["imap4flags"]; addflag "a b c"; removeflag "b";'},
    {"name": "flags-keep", "script": 'require ["imap4flags"]; addflag "\\\\Answered"; keep;'},
    {"name": "flags-hasflag", "script": 'require ["imap4flags"]; addflag "x"; if hasflag "x" { discard; }'},
    {"name": "flags-norequire", "script": 'addflag "x";'},
    # vacation
    {"name": "vacation", "script": 'require "vacation"; vacation "I am away";'},
    {"name": "vacation-days", "script": 'require "vacation"; vacation :days 3 :subject "Away" "I am away";'},
    {"name": "vacation-handle", "script": 'require "vacation"; vacation :handle "h1" "I am away";'},
    {"name": "vacation-from", "script": 'require "vacation"; vacation :from "me@example.com" "x";'},
    {"name": "vacation-norequire", "script": 'vacation "x";'},
    {"name": "vacation-discard", "script": 'require "vacation"; vacation "x"; discard;'},
    # Syntax
    {"name": "multiline", "script": 'require "vacation";\nvacation text:\nI am away.\n..dot\n.\n;'},
    {"name": "escapes", "script": 'require "fileinto"; fileinto "a\\"b\\\\c";'},
    {"name": "number-m", "script": 'if size :under 1M { discard; }'},
    {"name": "number-g", "script": 'if size :over 1G { discard; }'},
    {"name": "bad-missing-semicolon", "script": 'keep'},
    {"name": "bad-unknown-command", "script": 'frobnicate;'},
    {"name": "bad-unknown-test", "script": 'if frob { keep; }'},
    {"name": "bad-unknown-tag", "script": 'if header :frob "a" "b" { keep; }'},
    {"name": "bad-require-late", "script": 'keep; require "fileinto";'},
    {"name": "bad-unsupported", "script": 'require "nosuchext";'},
    {"name": "bad-unclosed", "script": 'if true { keep;'},
    {"name": "bad-string", "script": 'require "fileinto'},
    {"name": "bad-two-match", "script": 'if header :is :contains "a" "b" { keep; }'},
]
