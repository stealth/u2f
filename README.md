U2F utils
=========

Build
-----

Inside this dir,

	$ git clone https://github.com/signal11/hidapi

to get the HIDAPI for accessing the security token. Then just `make`.

You need to set up proper udev rules so the security token
appears as `/dev/hidraw*` device, with the permissions you prefer
or manually load the hid driver.

Part of this code is (C) 2014 Google Inc. under a BSD-ish license.
Please refer to the source code for details.


