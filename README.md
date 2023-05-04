# RUDICS (Router-Based Unrestricted Digital Internetworking Connectivity Solutions)

## Build Instructions

make\
sudo make install

## Installation Instructions

To use Iridium RUDICS (Router-Based Unrestricted Digital
Internetworking Connectivity Solutions) you must first open a RUDICS
account with your service provider.  You will need to supply the IP
address of your basestation and specify a port number rudics should
open for its connections; port 11113 is assumed below.  RUDICS depends
on this port being open on your basestation machine server. You may
have to open that port on your firewall; see below. You will also need
to supply SIM card IDs to add to your RUDICS account.  You should
request a telnet data-only service.

The following instructions assume Iridium will initiate connections
from their servers at 12.47.179.48-52. You should confirm this IP address
with your service provider.

The service provider will provide you a 'production' RUDICS phone
number for your account that will start with the prefix 88160000.
This should be used as the TELNUM or ALT_TELNUM on the glider.  All
calls made to that phone number will be routed to your basestation's
IP and the provided port effectively as a telnet connection.  The
software below handles and logs those connections.

To install, perform the following instructions as root. This
installation has been tested on Ubuntu 22

1) Make and copy rudicsd into /usr/local/bin. This requires a C++ compiler. 

2) Add the following entry to /etc/services:
      rudics  11113/tcp         # Iridium RUDICS server 
	  
where 11113 is the port number you provided to Iridium

3) If running a firewall, allow traffic on port 11113 from 12.47.179.48-52 

4) Ensure that xinetd is installed.  Ubuntu: apt-get install xinetd
 
5) Once installed, copy the supplied 'rudics' file to /etc/xinetd.d.  
   Then restart xinetd:
       systemctl restart xinetd.service

6) To test that your basestation machine will accept a RUDICS
connection, from the basestation issue the command:

	 telnet localhost 11113

You should get a login prompt.

## Operation

In order to use RUDICS, the Seaglider must be configured to call the
RUDICS phone number supplied by your service provider.  Typically the
Seaglider's primary number is configured to call the RUDICS number and
the alternate number is configured to call a modem hooked up to the
same basestation to act as a backup.

RUDICS replaces the modem-to-modem call that Iridium performs from
their ground station to the Seaglider basestation.  Instead the call
initiates a TCP/IP connection to the basestation.  Once the port is
opened, rudicsd is dispatched by xinetd to handle the call like a
telnet session.

rudicsd forks - the child process execs /bin/login to perform the
authentication of the glider, and the parent process remains active to
shuttle data to and from the open port and the login shell, as well as
monitor the connection for any dropped calls. /var/log/rudics.log can
be monitored to see relevent status and diagnostics.


