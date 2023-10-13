#!/usr/bin/env bash

#%
#% ${scriptName} - extract data from PFX file
#%
#% Usage: ${scriptName} <file.pfx> <password> [<name>]
#%
#% Where:
#%  <file.pfx>  : PFX file
#%  <password>  : password for PFX file
#%  <name>      : name to use for extracted files (default is "client")
#%
# To run it without parameters enter: "${scriptName} go"
#

pfxFile="$1"
password="$2"
name="$3"
name=${name:-client}

scriptName=$(echo ${0##*/})

if [[ $# -lt 2 ]]; then
    awk -v scriptName="${scriptName}" '/^#%/ {gsub("[$]{scriptName}", scriptName, $0); print substr($0,3)}' $0
#   grep '^#%' $0|xargs -I{} sh -c 'echo "{}"'
    exit 1
fi


if [[ -n ${password} ]]; then
    sPass="-passin pass:${password}"
fi

#openssl pkcs12 -in "${pfxFile}" -nocerts -nodes ${sPass}| openssl pkcs8 -nocrypt -out ${name}.key
openssl pkcs12 -in "${pfxFile}" -nocerts -nodes ${sPass}| sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' > ${name}.key
#openssl pkcs12 -in "${pfxFile}" -clcerts -nokeys ${sPass} | openssl x509 -out ${name}.crt
openssl pkcs12 -in "${pfxFile}" -clcerts -nokeys ${sPass} | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${name}.crt
openssl pkcs12 -in "${pfxFile}" -cacerts -nokeys -chain ${sPass} | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${name}_chain.crt

# decrypt encrypted private key:
# openssl pkey -in encrypted.key -out decrypted.key
