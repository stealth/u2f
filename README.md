U2F utils
=========

This u2f toolset contains small footprint u2f tools for enrolling
and signing operations as well as a _PAM_ module for authenticating
users on local services where they can physically plug in the
u2f token (i.e. _xdm_, _login_, _su_, ...).

I wrote this u2f stack in order to get familar with u2f crypto, the
shortcomings of u2f in general and weaknesses of other u2f stacks in
particular. Remote tools for u2f ssh etc. are underway.

Build
-----

Inside this dir,

	$ git clone https://github.com/signal11/hidapi

to get the HIDAPI for accessing the security token. Then:

	$ make
	$ make install

You need to set up proper udev rules so the security token
appears as `/dev/hidraw*` device, with the permissions you prefer
or manually load the hid driver.

Install
-------

To enroll a key you either use `u2f-enroll` or `pam-enroll`
if you want to enroll a key suitable for _PAM_ authentication:

```
localhost: # pam-enroll stealth
Remove token <ENTER>

Insert token of user 'stealth' and press token-button if available. Then <ENTER>

Got 631 bytes (sw=9000)

pubkey claims to be signed with cert (unchecked!):

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 18327115537361868814 (0xfe56fe7ae1ff180e)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Plug-up FIDO Internal Attestation CA #1
        Validity
            Not Before: Oct  3 08:06:48 2014 GMT
            Not After : Oct  3 08:06:48 2034 GMT
        Subject: CN=Plug-up FIDO Production Attestation #fe56fe7ae1ff180e
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:75:ea:06:60:e2:90:63:74:84:37:00:00:af:aa:
                    32:25:3e:82:7b:d8:48:74:93:a6:86:a5:68:4c:65:
                    ca:ce:09:8b:e8:bf:4b:87:25:3d:ef:96:b9:40:23:
                    01:06:fc:46:06:1f:7d:65:46:c1:6f:14:b2:5a:bf:
                    30:19:d8:f4:27
                ASN1 OID: prime256v1
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                76:2B:44:6F:F2:94:ED:32:2A:E4:29:09:4F:A9:84:D8:85:3E:35:80
            X509v3 Authority Key Identifier: 
                keyid:CF:A7:44:F2:A1:62:50:F0:39:E9:92:85:E3:DA:50:E7:7D:B0:3A:A8

    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:6b:5f:ea:7f:dd:ce:65:84:3b:25:d6:a6:fc:8a:
         4d:b7:3b:80:b1:e6:44:2e:ab:06:77:a9:3e:3d:b9:35:1f:22:
         02:20:59:5b:82:32:79:21:c2:8f:ad:20:62:b9:2a:ea:07:c4:
         37:a5:4d:46:a6:2c:8b:e6:ee:fb:69:5b:8a:b1:44:16

```

The public key along with the keyhandle has then been stored in `/etc/u2f/keys`:

```
localhost:# cat /etc/u2f/keys/_stealth
H=b67350 [...] 18273a626dc0743c
-----BEGIN PUBLIC KEY-----
MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA
[...]

[...]
SLI/caIDeYpo3lRlEdIWUX87A1cWC3YpCPJ89G1Hc9Fb9TtELXRiP3tHSfhgyVU=
-----END PUBLIC KEY-----
```

You can then add `pam_fido-u2f.so` to any _PAM_ service file (only
local services) for example to the _xdm_ display manager:

```
localhost: # cat /etc/pam.d/xdm
#%PAM-1.0
auth     include        common-auth
auth     required       pam_fido-u2f.so
account  include        common-account
password include        common-password
session  required       pam_loginuid.so
session  include        common-session
```

Next time someone logs in via _xdm_ an u2f token is required, which
must contain the private key belonging to the public part
stored in `/etc/u2f/keys`. Note that users which are not enrolled
via `pam-enroll` cannot longer login via _xdm_!


u2f limitations
---------------

Please note that 2FA tokens/mechanisms are of limited use to protect
shell access, since there are many ways to plant 2FA-less backdoors once
shell access has been gained by an attacker in the first place.
A Proper gateway and VPN setup is mandatory in order for 2FA to provide a
real security benefit. __Also note that the FIDO U2F standard chose a
NIST ECC curve (NIST P-256 aka `NID_X9_62_prime256v1`) for the crypto
operations.__ Yes, thats the same NIST that apparently already backdoored other 
crypto protocols. So you can consider `NID_X9_62_prime256v1` to be weak,
but it might be good enough as a second factor for medium secured sites.
Note again that USB tokens are subject to bad-USB style attacks. Some tokens
even have an API beyond FIDO U2F that allows for easy storage of keystrokes
and replay, once plugged in. So while it is in general a good idea to
have 2FA, you always add an additional attack vector to your site that
has not been there before.


_Part of this code is (C) 2014 Google Inc. under a BSD-ish license.
Please refer to the source code for details._



