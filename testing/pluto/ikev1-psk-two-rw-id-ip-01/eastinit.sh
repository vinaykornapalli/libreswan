/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
ipsec whack --impair suppress-retransmits
echo initdone
