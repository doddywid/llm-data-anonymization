when HTTP_REQUEST {
    HTTP::header remove "Accept-Encoding"
    HTTP::header replace Host "ce-tbs.la.f5poc.id"
    set detil [HTTP::method][HTTP::uri]
    log local0. "HTTP request vs-llmaas : [HTTP::method] [HTTP::uri] [HTTP::header "Content-Length"]"
    set embeddings 0
    set chat_completions 0
    if { [HTTP::method] eq "POST" && [HTTP::uri] starts_with "/v1/embeddings" }{
        set embeddings 1
        set content_length [HTTP::header "Content-Length"]
        HTTP::collect $content_length
    }
    if { [HTTP::method] eq "POST" && [HTTP::uri] starts_with "/v1/chat/completions" }{
        set chat_completions 1
        set content_length [HTTP::header "Content-Length"]
        HTTP::collect $content_length
    }
}
when HTTP_REQUEST_DATA {
    set payload [HTTP::payload]
    set old_len [string length $payload]
    set enc_key [class match -value key equals llm_anonymizer]

    #if { $chat_completions }{
        #detect stream mode in the request
     #   if {[regexp {\"stream\":\s*(true|false)} $payload match stream_value]} {
     #       log local0. "[HTTP::uri] - Stream value: $stream_value"
     #   } else {
            # If "stream" key is not found, log that as well
     #       log local0. "[HTTP::uri] - Stream key not found in payload"
     #   }
     #   log local0. "payload|$payload"
    #}

    if { $embeddings or $chat_completions }{
        #Anonymize SSN
        set match_counter 1
        while {[regexp {(\d{3}-\d{2}-\d{4})} $payload match]} {
            set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
            set replacement "\[ANMZD_$b64ciphertext\]"
            log local0. "Replacing to llmaas $match with $replacement"
            regsub {(\d{3}-\d{2}-\d{4})} $payload $replacement payload
            incr match_counter
        }

        #Anonymize Email
        set match_counter 1
        while {[regexp {([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})} $payload match]} {
            set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
            set replacement "\[ANMZD_$b64ciphertext\]"
            log local0. "Replacing to llmaas $match with $replacement"
            regsub {([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})} $payload $replacement payload
            incr match_counter
        }

        #Anonymize DoB
        set match_counter 1
        while {[regexp {(\d{2}/\d{2}/\d{4})} $payload match]} {
            set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
            set replacement "\[ANMZD_$b64ciphertext\]"
            log local0. "Replacing to llmaas $match with $replacement"
            regsub {(\d{2}/\d{2}/\d{4})} $payload $replacement payload
            incr match_counter
        }

        #Anonymize Phone Number
        set match_counter 1
        while {[regexp {(\d{1}-\d{3}-\d{3}-\d{4})} $payload match]} {
            set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
            set replacement "\[ANMZD_$b64ciphertext\]"
            log local0. "Replacing to llmaas $match with $replacement"
            regsub {(\d{1}-\d{3}-\d{3}-\d{4})} $payload $replacement payload
            incr match_counter
        }

        #Anonymize Salary
        set match_counter 1
        while {[regexp {(USD \$\d{1,3}(?:,\d{3})*(?=\s))} $payload match]} {
            set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
            set replacement "\[ANMZD_$b64ciphertext\]"
            log local0. "Replacing to llmaas $match with $replacement"
            regsub {(USD \$\d{1,3}(?:,\d{3})*(?=\s))} $payload $replacement payload
            incr match_counter
        }
    }
    HTTP::payload replace 0 $old_len $payload
}
when HTTP_RESPONSE {
    if { $chat_completions }{
        set content_length [HTTP::header "Content-Length"]
        HTTP::collect $content_length
    }
}
when HTTP_RESPONSE_DATA {
    set payload [HTTP::payload]
    set old_len [string length $payload]
    set enc_key [class match -value key equals llm_anonymizer]

    #De-anonymize
    set match_counter 1
    while {[regexp {(\[ANMZD_(.*?)\])} $payload match]} {
        regexp {\[ANMZD_(.*?)\]} $payload whole_match match
        set replacement [CRYPTO::decrypt -alg aes-128-ecb -key $enc_key [b64decode $match]]
        log local0. "Replacing response from llmaas $match back to $replacement"
        regsub {\[ANMZD_.*?\]} $payload $replacement payload
        incr match_counter
    }
    HTTP::payload replace 0 $old_len $payload
}
