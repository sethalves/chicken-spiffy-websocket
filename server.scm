#! /bin/sh
#| -*- scheme -*-
exec csi -include-path /usr/local/share/scheme -s $0 "$@"
|#

(use srfi-1)
(use srfi-4)

(use spiffy)
(use intarweb)
(use uri-common)
(use base64)
(use simple-sha1)

(define-record-type websocket
  (make-websocket inbound-port outbound-port send-bytes read-frame-proc)
  websocket?
  (inbound-port websocket-inbound-port)
  (outbound-port websocket-outbound-port)
  (send-bytes websocket-send-bytes)
  (read-frame-proc websocket-read-frame-proc))



(define (string->bytes str)
  ;; XXX this wont work unless it's all ascii.
  (let* ((lst (map char->integer (string->list str)))
         (bv (make-u8vector (length lst))))
    (let loop ((lst lst)
               (pos 0))
      (if (null? lst) bv
          (begin
            (u8vector-set! bv pos (car lst))
            (loop (cdr lst) (+ pos 1)))))))


(define (hex-string->string hexstr)
  ;; convert a string like "a745ff12" to a string
  (let ((result (make-string (/ (string-length hexstr) 2))))
    (let loop ((hexs (string->list hexstr))
               (i 0))
      (if (< (length hexs) 2)
          result
          (let ((ascii (string->number (string (car hexs) (cadr hexs)) 16)))
            (string-set! result i (integer->char ascii))
            (loop (cddr hexs)
                  (+ i 1)))))))


(define (websocket-send-frame ws data last-frame)
  (let* ((frame-fin (if last-frame 1 0))
         (frame-rsv1 0)
         (frame-rsv2 0)
         (frame-rsv3 0)
         (frame-opcode 1)
         (octet0 (bitwise-ior (arithmetic-shift frame-fin 7)
                              (arithmetic-shift frame-rsv1 6)
                              (arithmetic-shift frame-rsv2 5)
                              (arithmetic-shift frame-rsv3 4)
                              frame-opcode))

         (frame-masked 0)
         (frame-payload-length (cond ((< (u8vector-length data) 126)
                                      (u8vector-length data))
                                     ((< (u8vector-length data) 65536) 126)
                                     (else 127)))
         (octet1 (bitwise-ior (arithmetic-shift frame-masked 7)
                              frame-payload-length))
         (outbound-port (websocket-outbound-port ws)))

    (write-u8vector (u8vector octet0 octet1) outbound-port)

    (write-u8vector
     (cond
      ((= frame-payload-length 126)
       (u8vector
        (arithmetic-shift (bitwise-and (u8vector-length data) 65280) -8)
        (bitwise-and (u8vector-length data) 255)))
      ((= frame-payload-length 127)
       (u8vector
        0 0 0 0
        (arithmetic-shift
         (bitwise-and (u8vector-length data) 4278190080) -24)
        (arithmetic-shift
         (bitwise-and (u8vector-length data) 16711680) -16)
        (arithmetic-shift
         (bitwise-and (u8vector-length data) 65280) -8)
        (bitwise-and (u8vector-length data) 255)))
      (else (u8vector)))
     outbound-port)

    (write-u8vector data outbound-port)
    #t))


(define (websocket-send ws data)
  ;; XXX break up large data into multiple frames?
  (websocket-send-frame ws data #t))



(define (websocket-read-frame-payload inbound-port frame-payload-length
                                      frame-masked frame-masking-key)
  (let ((masked-data (read-u8vector frame-payload-length inbound-port)))
    (cond (frame-masked
           (let ((unmasked-data (make-u8vector frame-payload-length)))
             (let loop ((pos 0)
                        (mask-pos 0))
               (cond ((= pos frame-payload-length) unmasked-data)
                     (else
                      (let ((octet (u8vector-ref masked-data pos))
                            (mask (vector-ref frame-masking-key mask-pos)))
                        (u8vector-set!
                         unmasked-data pos (bitwise-xor octet mask))
                        (loop (+ pos 1) (modulo (+ mask-pos 1) 4))))))
             unmasked-data))
          (else
           masked-data))))


(define (websocket-read-frame ws)
  (let* ((inbound-port (websocket-inbound-port ws))
         ;; first byte
         (b0 (read-byte inbound-port)))
    (cond
     ((eof-object? b0) b0)
     (else
      (let* ((frame-fin (> (bitwise-and b0 128) 0))
             (frame-opcode (bitwise-and b0 15))
             ;; second byte
             (b1 (read-byte inbound-port))
             (frame-masked (> (bitwise-and b1 128) 0))
             (frame-payload-length (bitwise-and b1 127)))
        (cond ((= frame-payload-length 126)
               (let ((bl0 (read-byte inbound-port))
                     (bl1 (read-byte inbound-port)))
                 (set! frame-payload-length (+ (arithmetic-shift bl0 8) bl1))))
              ((= frame-payload-length 127)
               (xerror "8 byte payload length unsupported")))
        (let* ((frame-masking-key
                (if frame-masked
                    (let* ((fm0 (read-byte inbound-port))
                           (fm1 (read-byte inbound-port))
                           (fm2 (read-byte inbound-port))
                           (fm3 (read-byte inbound-port)))
                      (vector fm0 fm1 fm2 fm3))
                    #f)))
          (cond
           ((= frame-opcode 1)
            ;; (if (= frame-fin 1) ;; something?
            (websocket-read-frame-payload inbound-port frame-payload-length
                                          frame-masked frame-masking-key))
           ((= frame-opcode 8)
            (logger "websocket got close frame.\n")
            (generate-eof-object))
           ((= frame-opcode 10)
            ;; (logger "websocket got pong.\n")
            ;; we aren't required to respond to an unsolicited pong
            #t)
           (else
            (logger "websocket got unhandled opcode: " frame-opcode "\n")
            #f))))))))



(define (sha1-sum in-bv)
  (hex-string->string (string->sha1sum in-bv)))


(define (websocket-compute-handshake client-key)
  (let* ((key-and-magic
          (string-append client-key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
         (key-and-magic-sha1 (sha1-sum key-and-magic)))
    (base64-encode key-and-magic-sha1)))


(define (sec-websocket-accept-unparser header-contents)
  (map (lambda (header-content)
         (car (vector-ref header-content 0)))
       header-contents))


(header-unparsers
 (alist-update! 'sec-websocket-accept
                sec-websocket-accept-unparser
                (header-unparsers)))


(define (websocket-accept)
  (let* ((headers (request-headers (current-request)))
         (client-key (header-value 'sec-websocket-key headers))
         (ws-handshake (websocket-compute-handshake client-key))
         (ws (make-websocket
              (request-port (current-request))
              (response-port (current-response))
              websocket-send websocket-read-frame)))
    (with-headers
     `((upgrade ("WebSocket" . #f))
       (connection (upgrade . #t))
       (sec-websocket-accept (,ws-handshake . #t)))
     (lambda ()
       (send-response status: 'switching-protocols)))
    ws))



(define (make-websocket-handler app-code)
  (lambda (spiffy-continue)
    (cond ((equal? (uri-path (request-uri (current-request))) '(/ "web-socket"))
           (let ((ws (websocket-accept)))
             (app-code ws)))
          ((equal? (uri-path (request-uri (current-request))) '(/ ""))
           ((handle-file) "index.html"))
          (else
           ((handle-not-found) spiffy-continue)))))



(define (application-code ws)
  (websocket-send ws (string->bytes "testing"))
  (let ((data (websocket-read-frame ws)))
    (display "got from browser: ")
    (write (apply string (map integer->char (u8vector->list data))))
    (newline)))

(vhost-map `(("localhost" . ,(make-websocket-handler application-code))))
(server-port 8888)
;; (root-path "./web")
(start-server)
