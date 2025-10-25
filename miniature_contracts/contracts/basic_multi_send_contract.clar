;; Basic Multi-Send STX Contract
;; Allows sending a fixed amount of STX to multiple addresses in one transaction

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-AMOUNT (err u101))
(define-constant ERR-EMPTY-RECIPIENTS (err u102))
(define-constant ERR-TRANSFER-FAILED (err u103))
(define-constant ERR-INSUFFICIENT-BALANCE (err u104))

;; Contract owner
(define-constant CONTRACT-OWNER tx-sender)

;; Helper function to send STX to a single recipient
(define-private (send-stx-to-recipient (recipient principal) (amount uint))
  (stx-transfer? amount tx-sender recipient)
)

;; Helper function to process each recipient in the list
(define-private (process-recipient (recipient principal) (context {amount: uint, success: bool}))
  (let ((amount (get amount context))
        (current-success (get success context)))
    (if current-success
        (match (send-stx-to-recipient recipient amount)
          success {amount: amount, success: true}
          error {amount: amount, success: false})
        {amount: amount, success: false})))

;; Main function to send STX to multiple recipients
(define-public (multi-send-stx (recipients (list 50 principal)) (amount uint))
  (begin
    ;; Validate inputs
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (asserts! (> (len recipients) u0) ERR-EMPTY-RECIPIENTS)
    
    ;; Calculate total amount needed
    (let ((total-amount (* amount (len recipients))))
      
      ;; Check if sender has sufficient balance
      (asserts! (>= (stx-get-balance tx-sender) total-amount) ERR-INSUFFICIENT-BALANCE)
      
      ;; Process all recipients using fold
      (let ((result (fold process-recipient 
                          recipients 
                          {amount: amount, success: true})))
        
        ;; Check if all transfers were successful
        (asserts! (get success result) ERR-TRANSFER-FAILED)
        
        ;; Return success with total amount sent and number of recipients
        (ok {
          total-sent: total-amount,
          recipients-count: (len recipients),
          amount-per-recipient: amount
        })))))

;; Read-only function to calculate total cost
(define-read-only (calculate-total-cost (recipients (list 50 principal)) (amount uint))
  (let ((recipient-count (len recipients)))
    {
      amount-per-recipient: amount,
      total-recipients: recipient-count,
      total-cost: (* amount recipient-count)
    }))

;; Read-only function to check if sender has sufficient balance
(define-read-only (can-afford-multi-send (sender principal) (recipients (list 50 principal)) (amount uint))
  (let ((total-cost (* amount (len recipients)))
        (sender-balance (stx-get-balance sender)))
    {
      sender-balance: sender-balance,
      total-cost: total-cost,
      can-afford: (>= sender-balance total-cost)
    }))

;; Emergency function to check contract balance (for debugging)
(define-read-only (get-contract-info)
  {
    contract-balance: (stx-get-balance (as-contract tx-sender)),
    contract-owner: CONTRACT-OWNER
  })