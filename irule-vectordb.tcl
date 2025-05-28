when HTTP_REQUEST {
    HTTP::header remove "Accept-Encoding"
    HTTP::header replace Host "llmo.la.f5poc.id"
    set detil [HTTP::method][HTTP::uri]
    log local0. "HTTP request vs-vectordb : [HTTP::method] [HTTP::uri] [HTTP::header "Content-Length"]"
    set content_length [HTTP::header "Content-Length"]
    if { [HTTP::method] eq "PUT" && [HTTP::uri] starts_with "/collections/" }{
        HTTP::collect $content_length
    }
}

when HTTP_REQUEST_DATA {
    set payload [HTTP::payload]
    set old_len [string length $payload]
    set enc_key [class match -value key equals llm_anonymizer]

    #Anonymize SSN
    set match_counter 1
    while {[regexp {(\d{3}-\d{2}-\d{4})} $payload match]} {
        set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
        set replacement "\[ANMZD_$b64ciphertext\]"
        log local0. "Replacing to vectordb $match with $replacement"
        regsub {(\d{3}-\d{2}-\d{4})} $payload $replacement payload
        incr match_counter
    }

    #Anonymize Email
    set match_counter 1
    while {[regexp {([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})} $payload match]} {
        set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
        set replacement "\[ANMZD_$b64ciphertext\]"
        log local0. "Replacing to vectordb $match with $replacement"
        regsub {([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})} $payload $replacement payload
        incr match_counter
    }

    #Anonymize DoB
    set match_counter 1
    while {[regexp {(\d{2}/\d{2}/\d{4})} $payload match]} {
        set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
        set replacement "\[ANMZD_$b64ciphertext\]"
        log local0. "Replacing to vectordb $match with $replacement"
        regsub {(\d{2}/\d{2}/\d{4})} $payload $replacement payload
        incr match_counter
    }

    #Anonymize Phone Number
    set match_counter 1
    while {[regexp {(\d{1}-\d{3}-\d{3}-\d{4})} $payload match]} {
        set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
        set replacement "\[ANMZD_$b64ciphertext\]"
        log local0. "Replacing to vectordb $match with $replacement"
        regsub {(\d{1}-\d{3}-\d{3}-\d{4})} $payload $replacement payload
        incr match_counter
    }

    #Anonymize Salary
    set match_counter 1
    while {[regexp {(USD \$\d{1,3}(?:,\d{3})*(?=\s))} $payload match]} {
        set b64ciphertext [b64encode [CRYPTO::encrypt -alg aes-128-ecb -key $enc_key $match]]
        set replacement "\[ANMZD_$b64ciphertext\]"
        log local0. "Replacing to vectordb $match with $replacement"
        regsub {(USD \$\d{1,3}(?:,\d{3})*(?=\s))} $payload $replacement payload
        incr match_counter
    }
    HTTP::payload replace 0 $old_len $payload
}
