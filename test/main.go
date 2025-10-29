// test_email.go
package main

import (
	"log"
	"net/smtp"
)

func main() {
    // Test basic connection
    auth := smtp.PlainAuth("", "endrig@needgreatersglobal.com", "Assembly3637997Ab,", "mail.needgreatersglobal.com")
    
    to := []string{"andrewgouma@gmail.com"}
    msg := []byte("To: andrewgouma@gmail.com\r\n" +
        "Subject: Test\r\n" +
        "\r\n" +
        "Test message")
    
    err := smtp.SendMail("mail.needgreatersglobal.com:587", auth, "endrig@needgreatersglobal.com", to, msg)
    if err != nil {
        log.Fatal("Error:", err)
    }
    log.Println("Email sent successfully!")
}