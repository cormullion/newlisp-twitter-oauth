#!/usr/bin/env newlisp

;; @module twitter-oauth.lsp 
;; @description getting tweets from Twitter using OAuth 1.0a authentication 
;; @version 0.1
;; @author cormullion 2014-03-02 15:01:03
;;
;; <h2>Getting tweets from Twitter using OAuth</h2>
;; This file can download tweets from a named tweeter, using Twitter API version 1.1, OAuth 1.0A.
;; It follows @link https://dev.twitter.com/docs/auth/oauth) and uses 'curl'.
;; 
;; It uses (and patches) (load "/usr/share/newlisp/modules/crypto.lsp")
;; Usage:
;; <pre>
;; (set 'query 
;;    (list  
;;       (list "count" "2")
;;       (list "screen_name" "newlisp")
;;    ))
;; (set 'base-url "https://api.twitter.com/1.1/statuses/user_timeline.json")
;; (set 'results (get-tweets base-url query))
;; </pre>
;;
;; This module sometimes works on Mac OS X, and hasn't been tested on anything else... ;)

(module "crypto.lsp")

; fix hmac code in crypto.lsp versions <= 1.12 
(context crypto)
(define (hmac hash_fn msg_str key_str , blocksize opad ipad)
  (set 'blocksize 64)
  (set 'opad (dup "\x5c" blocksize))
  (set 'ipad (dup "\x36" blocksize))
  (if (> (length key_str) blocksize)
        (set 'key_str (hash_fn key_str true)))
  (set 'key_str (append key_str (dup "\000" (- blocksize (length key_str))))) ;; padding key with binary zeros
  (set 'opad (encrypt opad key_str))
  (set 'ipad (encrypt ipad key_str))
  (hash_fn (append opad (hash_fn (append ipad msg_str) true)) true))

(context 'Oauth)

; the Oauth parameters refer to an application that you have already created at apps.dev.twitter 
; load from a nearby file 'oauth-details.lsp' if possible, otherwise set them here:

(set 'oauth-details (string (env "HOME") "/projects/programming/newlisp-twitter-oauth/oauth-details.lsp"))

(if (file? oauth-details)
    (load oauth-details 'Oauth)
    (begin
        ; file should look like this:
        (set 'oauth_consumer_key "xxxxxxxxxxxxxxxxxxx") 
        (set 'oauth_token "111111111-xxxxxxxxxxxxxxxxxxxx")     ; access token for account
        (set 'oauth_version "1.0")
        (set 'oauth_token_secret "xxxxxxxxxxxxxxxxxxxx")        ; access token secret
        (set 'oauth_consumer_secret "xxxxxxxxxxxxxxxxxxxx")     ; API oauth secret
        ; eof
    ))

(set 'oauth_signature_method "HMAC-SHA1") ; a signature will eventually be created by running all the other request parameters and two secret values through a signing algorithm

; a simple URL encoding function
(define (url-encode str)
  (replace {([^a-zA-Z0-9-\._~])} (string str) (format "%%%2X" (char $1)) 0))

; build the parameter string from Oauth parameters and the query
(define (build-parameter-string request)
  (let (result '())
	(dolist (key ' (oauth_consumer_key 
                    oauth_nonce 
                    oauth_signature_method 
                    oauth_timestamp 
                    oauth_token 
                    oauth_version 
					))
		(push (string (term key) "=" (url-encode (eval key))) result -1) ; no point in URLencoding these I suppose
		)
	; add query request details
	(if request 
	    (dolist (key-value request)
	        (push (string (key-value 0) "=" (url-encode (key-value 1))) result -1)))
	; must be sorted! (took me half an hour to work this out :)
	(join (sort result) "&")))

; build the signature base string
(define (build-signature-base-string method base-url parameter-string)
   (string (upper-case method) "&" (url-encode base-url) "&" (url-encode parameter-string)))

; build the oauth signature header
(define (build-oauth-signature signature-base-string signing-key)	
    (base64-enc (crypto:hmac crypto:sha1 signature-base-string signing-key)))

; build the authorization header
(define (build-header-string)
   (let (result (string "Authorization: OAuth "))
	(dolist (key '(oauth_consumer_key 
				   oauth_nonce 
				   oauth_signature  ; <------ it goes in this time
				   oauth_signature_method 
				   oauth_timestamp 
				   oauth_token 
				   oauth_version))
		(push (term key) result -1)
		(push "=\"" result -1)
		(push (string (url-encode (eval key)) "\", " ) result -1))
	(chop result 2)))

; convert list of query terms into string
(define (make-request-query query-list)
  (let (result '())
    (dolist (key-value query-list)
	        (push (string (key-value 0) "=" (url-encode (key-value 1))) result -1))
	(join result "&")))

;; @syntax (get-tweets <string> <assoc-query-params>)
;; @param <string> The base URL
;; @param <assoc-query-params> An association list containing some query parameters (key/value pairs).
;; @return (If you're lucky) the JSON result of the 'curl' command.
;; @example
;; (get-tweets 
;;    "https://api.twitter.com/1.1/statuses/user_timeline.json" 
;;    (list  (list "count" "200") (list "screen_name" "newlisp"))) 
;;
(define (get-tweets base-url query-params)
   (let (oauth_nonce oauth_timestamp signing-key 
         request-query signature-base-string oauth_signature curl-command)
    
    ; these timestamps have to be set for each and every request otherwise twitter won't like it
    (set 'oauth_nonce (0 32 (base64-enc (uuid)))) ; a unique token for each request value
    (set 'oauth_timestamp (date-value))           ; timestamp will be number of seconds since Unix epoch 
    
    ; build a signing key from auth_consumer_secret and oauth-token_secret
    (set 'signing-key (string (url-encode oauth_consumer_secret) "&" (url-encode oauth_token_secret)))
    
    ; get the query parameters into the right form
    (set 'request-query (make-request-query query))
    
    ; make a signature-base-string
    (set 'signature-base-string 
        (build-signature-base-string "GET" base-url (build-parameter-string query)))
    
    ; make the signature using crypto NSA stuff
    (set 'oauth_signature (build-oauth-signature signature-base-string signing-key))

    (set 'curl-command 
        (format {curl --silent --get '%s' --data '%s' --header '%s'} (list base-url request-query (build-header-string))))
    ; enough oauth crap, just do it (TM)
    (json-parse (first (exec curl-command)))))

; end

[text]
; entry point 
; supply the query parameters as a nested assoc list:

(set 'query 
    (list  
       (list "count" "200")
       (list "screen_name" "newlisp")
    ))

(set 'base-url "https://api.twitter.com/1.1/statuses/user_timeline.json")

(set 'results (get-tweets base-url query))

(println results)

(exit)
[/text]