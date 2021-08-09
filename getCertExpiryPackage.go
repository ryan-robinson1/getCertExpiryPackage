/*
	Ryan Robinson, 2021

	getCertExpiry is a go command line tool to find the expiration dates of given server certs and check if they are expired

*/

package getCertExpiryPackage

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io/ioutil"
	"time"
)

//Takes a time and returns true if the time has past, false otherwise
func isTimePast(t time.Time) bool {
	delta := time.Since(t)
	return delta > 0
}

//Connects to address and returns 0 if the cert is valid and 1 if it is expired in addition to the cert expiration date. If the
//server does not support SSL certificates, return 3 and an error. If the inputted client certs are invalid, return 5 and error
func GetCertExpiry(address string, cert string, key string, ca string, insecure bool) (int, string, error) {
	caCertPool := x509.NewCertPool()
	tlsCert := tls.Certificate{}

	if cert != "" && key != "" {
		tempCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return 5, "", err
		}
		tlsCert = tempCert
	}
	if ca != "" {
		caCert, err := ioutil.ReadFile(ca)
		if err != nil {
			return 5, "", err
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}
	conf := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: insecure,
	}
	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return 3, "", err
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	if isTimePast(expiry) {
		return 1, expiry.Format("2006-01-02 15:04:05"), nil
	}
	return 0, expiry.Format("2006-01-02 15:04:05"), nil
}

//Parses the first argument for the address and then looks for flags. Currently the only flag is the "insecure" flag which allows for insecure tls connections
func ParseArgs(args []string) (string, string, string, string, bool, error) {
	urlFlag := flag.String("u", "", "url in the format 'url:port.' Specify without flag by inputting as last arg")
	certFlag := flag.String("c", "", "Client cert file")
	keyFlag := flag.String("k", "", "Client key file")
	caFlag := flag.String("a", "", "CA cert file")
	insecureFlag := flag.Bool("i", false, "allows untrusted cert connections")

	flag.Parse()
	if *urlFlag == "" {
		return flag.Arg(0), *certFlag, *keyFlag, *caFlag, *insecureFlag, nil
	}
	if len(args) == 1 {
		return "", "", "", "", false, errors.New("err: no args, use --help for args")
	}
	return *urlFlag, *certFlag, *keyFlag, *caFlag, *insecureFlag, nil
}
