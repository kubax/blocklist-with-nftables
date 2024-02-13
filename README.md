blocklist-with-nftables
====================
Use at your own risk :)

Tested on Debian Bookworm.

## What it does ##
This script automatically downloads blocklist from sources you can define (in the blocklist.pl).

Then it will create two ipset lists. One for IPv4 IPs and one for IPv6 IPs.

It will then create an BLOCKLIST iptables/BLOCKLIST ip6tables chain which logs access attempts from blocked IPs (matched by the ipset lists), to your syslog and DROP the request. Also it will create an forward from your INPUT queue to the BLOCKLIST chain.

Next time you run the script it will check if the IP is allready blocked or needs to be added. Also it will verify if the IP has been removed from your lists and remove it from the ipset as well. 

This can be overruled by an white and blacklist you can define in the corresponding whitelist.xt and blacklist.

Changes
--------
- V1.1.7: @pingou2712: Update README.md in order to include systemd
- V1.1.6: @pingou2712: add option to block bridge instead
- V1.1.5: @kubax: greatly improved speed. switching to nft -f instead of pushing every
- V1.1.4: switch to nftables
- V1.1.3: @Sheogorath-SI: increase maxelemt to fit more than 65536 entries
- V1.1.2: @kubax: add support for ip6tables (iptables on Arch Linux refuses ipv6 rules)
- V1.1.1: short Help (-h) and Cleanup (-c) available. Binary should now be found automatically.
- V1.1.0: blocklist-with-ipset is now IPV6 compatible (Yayyy :) )
- V1.0.4: Path to white and blacklist is now set automatically
- V1.0.3: Now you can set multiple blocklist sources
- V1.0.2: Added a whitelist and blacklist

<br>
**!!! IMPORTANT !!!!**

When upgrading to V1.1.2+ you might want to manually delete the iptables INPUT BLOCKLIST rule with the target match-set blocklist-v6 src

--

When upgrading from a version lower than 1.1.0 you might have to manually remove duplicated INPUT Rules or run

	./blocklist -c

*Ignore error messages that might show up.*

The script uses various binarys like iptables, ipset. If the script complains that it can't find an specific binary make sure it is in the ENV Path of the script. If not add the path to the ENV Variable.

	$ENV{'PATH'}= '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';

(You can find out where your binarys are with "which" e.g. "which iptables")

## INSTALL ##

1. Make sure you have ipset and the Data::Validate::IP Perl Module installed! If not you can usually install it with your distribution software management tool. E.g. apt for Debian/Ubuntu/Mint.

		apt-get install ipset libdata-validate-ip-perl

2. Download the ZIP, or Clone the repository, to a folder on your system.

3. Open blocklist.pl with your favorite text editor and set up your blocklist urls. Two are included as default. You can enhance or edit as you like. The destination URL should be an direct link to an Text file though.

        my @listUrl = ("http://lists.blocklist.de/lists/all.txt", "http://www.infiltrated.net/blacklisted");

        *You can for example add an list like this*

        my @listUrl = ("http://lists.blocklist.de/lists/all.txt", "http://www.infiltrated.net/blacklisted", "http://www.superblocksite.org/anotherBlocklist.txt");

4. Schedule the script execution using either a cron job or systemd (see below).

5. Create an logrotate for the logfile. E.g. under /etc/logrotate.d/blocklist

		/var/log/blocklist
		{
			rotate 4
        	daily
			missingok
			notifempty
			delaycompress
			compress
		}

6. If you have an ip you definitly want to block just put it in blacklist. If you have an IP you definitly never want to have blocked put it in whitelist. This two files are just text lists seperated by new lines. So for example

		#blacklist
		2.2.2.2
		3.3.3.3

		#and in whitelist
		4.4.4.4
	 	5.5.5.5

That's it. If you want to manually run the script just cd to the folder where the script is located and run 

	./blocklist.pl

## Scheduling Execution
### Using a Cron Job
Create an cronjob. I have and hourly cronjob in /etc/crontab

        0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl > /dev/null

	Or in order to block bridge instead:

        0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl -b > /dev/null

### Using systemd
Create `blocklist.service` and `blocklist.timer` in `/etc/systemd/system/`.

In `blocklist.service`:

```ini
[Unit]
Description=Run blocklist script

[Service]
Type=oneshot
ExecStart=/usr/bin/perl /path/to/the/script/blocklist.pl
```

In `blocklist.timer`:

```ini
[Unit]
Description=Timer for blocklist script

[Timer]
# Start 1 minute after boot
OnBootSec=1min
# Execute every hour
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl enable blocklist.timer
sudo systemctl start blocklist.timer
```

To use the bridge blocking option with systemd, modify `ExecStart` in `blocklist.service` to include `-b`.

## CLEANUP ##
If you want to remove the iptables rules and ipset lists just run


	./blocklist.pl -c

## FORWARD CONNECTION ##
If you want to block bridge instead, add the -b flag:

	./blocklist.pl -b

## Credits ##

virus2500: https://github.com/virus2500

Sheogorath-SI: https://github.com/Sheogorath-SI
