/testing/guestbin/swan-prep --x509 --x509name east-nosan
certutil -D -n west -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
