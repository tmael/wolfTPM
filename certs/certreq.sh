#!/bin/bash

echo Run from wolftpm root
echo Run ./examples/crl/crl first to generate the CSR


# Make sure required CA files exist and are populated
rm ./certs/index.txt 
touch ./certs/index.txt 
if [ ! -f ./certs/serial ]; then
	echo 1000 > ./certs/serial
fi
if [ ! -f ./certs/crlnumber ]; then
	echo 2000 > ./certs/crlnumber
fi

if [ $1 == clean ]; then
	rm ./certs/*.pem
	rm ./certs/*.der
	rm ./certs/*.old
fi


# Generate RSA 2048-bit CA
if [ ! -f ./certs/ca-rsa-key.pem ]; then
	openssl req -new -newkey rsa:2048 -keyout ./certs/ca-rsa-key.pem -nodes -out ./certs/ca-rsa-cert.csr -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
    openssl x509 -req -in ./certs/ca-rsa-cert.csr -days 1000 -extfile ./certs/ca-rsa.cnf -extensions v3_ca -signkey ./certs/ca-rsa-key.pem -out ./certs/ca-rsa-cert.pem
    rm ./certs/ca-rsa-cert.csr

	openssl x509 -in ./certs/ca-rsa-cert.pem -inform PEM -out ./certs/ca-rsa-cert.der -outform DER
	openssl rsa -in ./certs/ca-rsa-key.pem -inform PEM -out ./certs/ca-rsa-key.der -outform DER

	# generate CRL
	openssl ca -config ./certs/ca-rsa.cnf -gencrl -crldays 1000 -out ./certs/ca-rsa.crl -keyfile ./certs/ca-rsa-key.pem -cert ./certs/ca-rsa-cert.pem
fi

# Sign RSA certificate
if [ -f ./certs/client-rsa-cert.csr ]; then
	openssl ca -config ./certs/ca-rsa.cnf -extensions usr_cert -days 3650 -notext -md sha256 -in ./certs/client-rsa-cert.csr -out ./certs/client-rsa-cert.pem -batch
	openssl x509 -in ./certs/client-rsa-cert.pem -outform der -out ./certs/client-rsa-cert.der
fi


# Generate ECC 256-bit CA
if [ ! -f ./certs/ca-ecc-key.pem ]; then
	openssl ecparam -out ./certs/ca-ecc-key.par -name prime256v1
	openssl req -config ./certs/ca-ecc.cnf -extensions v3_ca -x509 -nodes -newkey ec:./certs/ca-ecc-key.par -keyout ./certs/ca-ecc-key.pem -out ./certs/ca-ecc-cert.pem -sha256 -days 7300 -batch -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
	rm ./certs/ca-ecc-key.par

	openssl x509 -in ./certs/ca-ecc-cert.pem -inform PEM -out ./certs/ca-ecc-cert.der -outform DER
	openssl ec -in ./certs/ca-ecc-key.pem -inform PEM -out ./certs/ca-ecc-key.der -outform DER

	# generate CRL
	openssl ca -config ./certs/ca-ecc.cnf -gencrl -crldays 1000 -out ./certs/ca-ecc.crl -keyfile ./certs/ca-ecc-key.pem -cert ./certs/ca-ecc-cert.pem
fi


# Sign ECC Certificate
if [ -f ./certs/client-ecc-cert.csr ]; then
	# NOT APPLICABLE BECAUSE PRIVATE KEY IS IN TPM
	#openssl ecparam -out ./certs/client-ecc-key.par -name prime256v1
	#openssl req -config ./certs/ca-ecc.cnf -sha256 -new -newkey ec:./certs/client-ecc-key.par -keyout ./certs/client-ecc-key.pem -out ./certs/client-ecc-cert.csr -subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
	#rm ./certs/client-ecc-key.par

	openssl ca -config ./certs/ca-ecc.cnf -extensions usr_cert -days 3650 -notext -md sha256 -in ./certs/client-ecc-cert.csr -out ./certs/client-ecc-cert.pem -batch
	openssl x509 -in ./certs/client-ecc-cert.pem -outform der -out ./certs/client-ecc-cert.der
fi
