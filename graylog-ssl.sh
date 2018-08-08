#!/bin/bash
# Author: Yevgeniy Goncharov aka xck, http://sys-adm.in
# Script for generate GrayLog certs
#
# Manual changes
# rest_listen_uri (this needs to start with https://)
# web_listen_uri (this needs to start with https://)
# rest_enable_tls (set to ‘true’)
# rest_tls_cert_file (point to the previously created ssl certificate)
# rest_tls_key_file (point to the previously created ssl encrypted key)
# rest_tls_key_password (set the key password)
# web_enable_tls (set to ‘true)
# web_tls_cert_file (point to the previously created ssl certificate)
# web_tls_key_file (point to the previously created ssl encrypted key)

PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)
ME=`basename "$0"`

DATE=$(date +%d-%m-%Y_%H-%M)

# Make server.conf backup
cp /etc/graylog/server/server.conf $SCRIPT_PATH/server.conf-$DATE

# Determine hostname and make https links
HOSTNAME=`cat /etc/hostname`
WEBHOSTNAME='https://'`cat /etc/hostname`
RESTPORT='9000/api/'
WEBPORT='9000/'

# Adding https and hostname to graylog conf file
sed -i '/rest_listen_uri/{s/#//}' /etc/graylog/server/server.conf
sed -i '/rest_listen_uri/{s/=.*/=/}' /etc/graylog/server/server.conf
# sed -i "/rest_listen_uri =/ s|$| $WEBHOSTNAME:$RESTPORT|" /etc/graylog/server/server.conf
sed -i '/web_listen_uri/{s/#//}' /etc/graylog/server/server.conf
sed -i '/web_listen_uri/{s/=.*/=/}' /etc/graylog/server/server.conf
# sed -i "/web_listen_uri =/ s|$| $WEBHOSTNAME:$WEBPORT|" /etc/graylog/server/server.conf

# Create SSL self-signed certificate
GRAYLOGCERTIFICATE='graylogcertificate.pem'
GRAYLOGENCRYPTEDKEY='graylogprivatekey.pem'
GRAYLOGPRIVATEKEY='graylogprivatekey-unencrypted.pem'
GRAYLOGP12='graylog.p12'
SSLPATH='/opt/ssl'
VALIDITY='9999'

# Self-signed certificate
sudo mkdir -p $SSLPATH
cd $SSLPATH

echo -n "Please specify a private key password: "
read -s PRIVATEKEYPASS
echo -e "\n"

openssl req -newkey rsa:2048 -nodes -keyout $GRAYLOGPRIVATEKEY -x509 -days $VALIDITY -out $GRAYLOGCERTIFICATE -passin pass:$PRIVATEKEYPASS \
-subj "/OU=Graylog/CN=$HOSTNAME/"
openssl pkcs12 -inkey $GRAYLOGPRIVATEKEY -in $GRAYLOGCERTIFICATE -export -out $GRAYLOGP12 -passin pass:$PRIVATEKEYPASS -passout stdin <<PASS
$PRIVATEKEYPASS
PASS

# Encrypting private key
openssl pkcs8 -in $GRAYLOGPRIVATEKEY -topk8 -out $GRAYLOGENCRYPTEDKEY -passin pass:$PRIVATEKEYPASS -passout stdin <<PASS
$PRIVATEKEYPASS
PASS

# Trusting CA Certificate
cp $GRAYLOGCERTIFICATE /etc/pki/ca-trust/source/anchors/
update-ca-trust extract

# Enable SSL on Graylog
TLS='true'
CERTPATH="$SSLPATH/$GRAYLOGCERTIFICATE"
KEYPATH="$SSLPATH/$GRAYLOGENCRYPTEDKEY"
KEYPWD="$PRIVATEKEYPASS"

sed -i '/rest_enable_tls/{s/#//}' /etc/graylog/server/server.conf
sed -i '/rest_enable_tls/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/rest_enable_tls =/ s/$/ ${TLS}/" /etc/graylog/server/server.conf
sed -i '/rest_tls_cert_file/{s/#//}' /etc/graylog/server/server.conf
sed -i '/rest_tls_cert_file/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/rest_tls_cert_file =/ s|$| ${CERTPATH}|" /etc/graylog/server/server.conf
sed -i '/rest_tls_key_file/{s/#//}' /etc/graylog/server/server.conf
sed -i '/rest_tls_key_file/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/rest_tls_key_file =/ s|$| ${KEYPATH}|" /etc/graylog/server/server.conf
sed -i '/rest_tls_key_password/{s/#//}' /etc/graylog/server/server.conf
sed -i '/rest_tls_key_password/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/rest_tls_key_password =/ s|$| ${KEYPWD}|" /etc/graylog/server/server.conf
sed -i '/web_enable_tls/{s/#//}' /etc/graylog/server/server.conf
sed -i '/web_enable_tls/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/web_enable_tls =/ s/$/ ${TLS}/" /etc/graylog/server/server.conf
sed -i '/web_tls_cert_file/{s/#//}' /etc/graylog/server/server.conf
sed -i '/web_tls_cert_file/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/web_tls_cert_file =/ s|$| ${CERTPATH}|" /etc/graylog/server/server.conf
sed -i '/web_tls_key_file/{s/#//}' /etc/graylog/server/server.conf
sed -i '/web_tls_key_file/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/web_tls_key_file =/ s|$| ${KEYPATH}|" /etc/graylog/server/server.conf
sed -i '/web_tls_key_password/{s/#//}' /etc/graylog/server/server.conf
sed -i '/web_tls_key_password/{s/=.*/=/}' /etc/graylog/server/server.conf
sed -i "/web_tls_key_password =/ s|$| ${KEYPWD}|" /etc/graylog/server/server.conf

# Restart services
systemctl restart elasticsearch.service
systemctl restart graylog-server.service

