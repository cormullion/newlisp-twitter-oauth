newlisp-twitter-oauth
=====================

This file can download tweets from a named tweeter, using Twitter API version 1.1, OAuth 1.0A.
It followshttps://dev.twitter.com/docs/auth/oauth) and uses 'curl'.

It uses (and currently patches) "/usr/share/newlisp/modules/crypto.lsp"
Usage:

    (set 'query 
      (list  
         (list "count" "2")
         (list "screen_name" "newlisp")
      ))
    (set 'base-url "https://api.twitter.com/1.1/statuses/user_timeline.json")
    (set 'results (get-tweets base-url query))

This module sometimes works on Mac OS X, and hasn't been tested on anything else... ;)
