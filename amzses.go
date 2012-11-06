// Copyright 2011 Numrotron Inc.
// Use of this source code is governed by an MIT-style license
// that can be found in the LICENSE file.
//
// Developed at www.stathat.com by Patrick Crosby
// Contact us on twitter with any questions:  twitter.com/stat_hat

// amzses is a Go package to send emails using Amazon's Simple Email Service.
package amzses

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/stathat/jconfig"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	endpoint = "https://email.us-east-1.amazonaws.com"
)

type SES struct {
	accessKey, secretKey string
}

// for your convenience, a struct you can use with encoding/xml on the server's response
type AmazonResponse struct {
	MessageId string `xml:"SendEmailResult>MessageId"`
	RequestId string `xml:"ResponseMetadata>RequestId"`
}

func Init() *SES {
	config := jconfig.LoadConfig("/etc/aws.conf")
	return &SES{config.GetString("aws_access_key"), config.GetString("aws_secret_key")}
}

func InitAuth(accessKey, secretKey string) *SES {
	return &SES{accessKey, secretKey}
}

func (ses *SES) sendMail(from, to, subject, body, format string) (string, error) {
  data := make(url.Values)
	data.Add("Action", "SendEmail")
	data.Add("Source", from)
	data.Add("Destination.ToAddresses.member.1", to)
	data.Add("Message.Subject.Data", subject)
	data.Add(fmt.Sprintf("Message.Body.%s.Data", format), body)
	data.Add("AWSAccessKeyId", ses.accessKey)

	return ses.sesGet(data)
}

func (ses *SES) SendMail(from, to, subject, body string) (string, error) {
	return ses.sendMail(from, to, subject, body, "Text")
}

func (ses *SES) SendHTMLMail(from, to, subject, body string) (string, error) {
  return ses.sendMail(from, to, subject, "Html")
}

func (ses *SES) authorizationHeader(date string) []string {
	h := hmac.New(sha256.New, []uint8(ses.secretKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", ses.accessKey, signature)
	return []string{auth}
}

func (ses *SES) sesGet(data url.Values) (string, error) {
	urlstr := fmt.Sprintf("%s?%s", endpoint, data.Encode())
	endpointURL, _ := url.Parse(urlstr)
	headers := map[string][]string{}

	now := time.Now().UTC()
	// date format: "Tue, 25 May 2010 21:20:27 +0000"
	date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	headers["Date"] = []string{date}
	headers["X-Amzn-Authorization"] = ses.authorizationHeader(date)

	req := http.Request{
		URL:        endpointURL,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     headers,
	}

	r, err := http.DefaultClient.Do(&req)
	if err != nil {
		log.Printf("http error: %s", err)
		return "", err
	}

	resultbody, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if r.StatusCode != 200 {
		log.Printf("error, status = %d", r.StatusCode)

		log.Printf("error response: %s", resultbody)
		return "", errors.New(string(resultbody))
	}

	return string(resultbody), nil
}
