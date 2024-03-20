#!/usr/bin/perl
use strict; 
use warnings;
use FindBin '$Bin';
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use Getopt::Std;
use Fcntl ':flock';
use File::Temp qw(tempfile);
open my $self, '<', $0 or die "Couldn't open self: $!";
flock $self, LOCK_EX | LOCK_NB or die "This script is already running";
no if ($] >= 5.018), 'warnings' => 'experimental::smartmatch';
################################################################
###### Script to parse a Blocklist list. Block new IP     ######
###### and unblock deleted entrys                         ######
###### Multiple list possible. IPV4 and IPV6 supported    ######
################################################################

## config ##
my @listUrl     = ("http://lists.blocklist.de/lists/all.txt");
my $tmpDir      = "/tmp";
my $logFile     = "/var/log/blocklist";
my $whiteList   = "/etc/blocklist/whitelist";
my $blackList   = "/etc/blocklist/blacklist";

## binarys ##
## ! Notice ! Changing these values shouldn't be needed anymore
## I'll leave it here just in case none of the paths below match.
$ENV{'PATH'}    = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
my $nft         = "nft";
my $grep        = "grep";
my $rm          = "rm";
my $wget        = "wget";

## plain variables ##
my($row, $Blocklist, $line, $check, $checkLine, $result, $output, $url, $ipRegex, $message, %opt, $opt);

my ($added, $count, $removed, $skipped, $added_ipv4, $added_ipv6);
$added = $count = $removed = $skipped = $added_ipv4 = $added_ipv6 = 0;

## init arrays ##
my @fileArray = ();
my @ipsetArray = ();
my @whiteListArray = ();
my @blackListArray = ();
## init hashes for faster searching
my %whiteListArray;
my $blackListArray;
my %ipsetArray;
my %fileArray;

my $dateTime;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
my @days = qw(Sun Mon Tue Wed Thu Fri Sat Sun);

my $TABLE = "blocklist";
my $tmp_v4 = new File::Temp( UNLINK => 1);
my $tmp_v6 = new File::Temp( UNLINK => 1);
my $tmp_ipv4 = "";
my $tmp_ipv6 = "";
my $tmp_bridge_or_nat = new File::Temp( UNLINK => 1);
my $bridge_nat_Option = 0;

&init();

############# init ##################
#### check if we got any options ####
#### and decide where to go      ####
#####################################

sub init {
    $opt = 'hcbn';
    getopts( "$opt", \%opt );
    usage() if $opt{h};
    cleanupAll() if $opt{c};
    exit if $opt{c};
    $bridge_nat_Option = 1 if $opt{b};
    $bridge_nat_Option = 2 if $opt{n};
    # else start main subroutine
    main();
}
############## end init #############

############ usage ##################
#### Some info about this script ####
#####################################
sub usage() {
    print STDERR << "EOF";
    blocklist-with-nftable
    
    This script downloads and parses Text files with IPs and blocks them. 
    Just run ./blocklist.pl
    
    If you want to clean everything up run
    ./blocklist.pl -c

    If you want block ip on bridge table run
    ./blocklist.pl -b

    If you want block ip on inet table prerouting to protect nat run
    ./blocklist.pl -n

EOF
    exit;
}
#****************************#
#*********** MAIN ***********#
#****************************#
sub main {
    logging("Starting blocklist refresh");
    logging("Removing Blocklist Tables");
    &cleanupAll();
    logging("Generating Whitelist Array");
    &getWhiteListArray();
    logging("Generating Blacklist Array");
    &getBlackListArray();
    logging("Generating Blocklist Array");
    &getFileArray();
    logging("Adding IPs to Blocklist");
    &addIpsToBlocklist();
    logging("Adding Blocklist to ruleset");
    &applyBlocklist();
    logging("Starting Cleanup");
    &cleanup();

    exit;
}
#***** END MAIN *****#


#****************************#
#******* Subroutines ********#
#****************************#

########## getFileArray #############
## downloads the Blocklist.txt and ##
## pushes it into an array         ##
#####################################
sub getFileArray {
    foreach $url (@listUrl) {
        $count++;
        `$wget -q -O $tmpDir/Blocklist_$count $url && echo "Downloaded temp file to $tmpDir/Blocklist_$count" || echo "Can not download file.... stopping"`;

        open(INFO, "$tmpDir/Blocklist_$count") or die("Could not open file.");
        foreach $line (<INFO>) {
            push(@fileArray, $line);
        }

        close(INFO);
    }
    chomp(@fileArray);
    %fileArray = map {$_ => 1 } @fileArray;
}
####### END getFileArray ##########

######### getWhiteListArray ######
## puts all ips from our        ##
## $whitelist into              ##
## array whiteListArray         ##
##################################

sub getWhiteListArray {
    open(INFO, $whiteList) or die("Could not open Whitelist.");
    foreach $line (<INFO>) {
        push(@whiteListArray, $line);
    }

    close(INFO);
    chomp(@whiteListArray);
}
##### END getWhiteListArray #####

######### getBlackListArray ######
## puts all ips from our        ##
## $whitelist into              ##
## array blackListArray         ##
##################################

sub getBlackListArray {
    open(INFO, $blackList) or die("Could not open Blacklist.");
    foreach $line (<INFO>) {
        push(@blackListArray, $line);
    }

    close(INFO);
    chomp(@blackListArray);
}
##### END getBlackListArray #####

######## addIpsToBlocklist ######
## adds IPs to our blocklist   ##
#################################

sub addIpsToBlocklist {

    #Prepare ipv4 and ipv6 set
    $tmp_ipv4 = "\tset ipv4 {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = {\n";
    $tmp_ipv6 = "\tset ipv6 {
\t\ttype ipv6_addr
\t\tflags interval
\t\telements = {\n";
    foreach $line (uniq(@blackListArray)) {
        if ((exists $ipsetArray{"$line"}) ||    ($line ~~ @whiteListArray)) {
            $skipped++;
        } else {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
			$tmp_ipv4 = "${tmp_ipv4}\t\t\t$line,\n";
			$added_ipv4++;
                } else {
			$tmp_ipv6 = "${tmp_ipv6}\t\t\t$line,\n";
			$added_ipv6++;
                }
                $added++;
		#$message = "added $line";
		#logging($message);
            } else {
                $skipped++;
            }
        }
    }
    foreach $line (uniq(@fileArray)) {
        if ((exists $ipsetArray{"$line"}) || ($line ~~ @whiteListArray)) {
            $skipped++;
        } else {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
			$tmp_ipv4 = "${tmp_ipv4}\t\t\t$line,\n";
			$added_ipv4++;
                } else {
			$tmp_ipv6 = "${tmp_ipv6}\t\t\t$line,\n";
			$added_ipv6++;
                }
                $added++;
		#$message = "added $line";
		#logging($message);
            } else {
                $skipped++;
            }
        } 
    } 
    $tmp_ipv4 = "${tmp_ipv4}\t\t}
\t}\n";
    $tmp_ipv6 = "${tmp_ipv6}\t\t}
\t}\n";

    # Build tmp_v4 and v4 OR tmp_bridge
    if ( $bridge_nat_Option == 0 )
    {
        print $tmp_v4 "table ip $TABLE {\n";
	print $tmp_v4 "$tmp_ipv4";
        print $tmp_v4 "\tchain input {
\t\ttype filter hook input priority 100; policy accept;
\t\tip saddr \@ipv4 log prefix \"Blocklist Dropped: \" drop
\t}
}\n";

        print $tmp_v6 "table ip6 $TABLE {\n";
	print $tmp_v6 "$tmp_ipv6";
        print $tmp_v6 "\tchain input {
\t\ttype filter hook input priority 100; policy accept;
\t\tip6 saddr \@ipv6 log prefix \"Blocklist Dropped: \" drop
\t}
}\n";

    } elsif ( $bridge_nat_Option == 1 ) {
        print $tmp_bridge_or_nat "table bridge $TABLE {\n";
	print $tmp_bridge_or_nat "$tmp_ipv4";
	print $tmp_bridge_or_nat "$tmp_ipv6";
        print $tmp_bridge_or_nat "\tchain prerouting {
\t\ttype filter hook prerouting priority 100; policy accept;
\t\tip saddr \@ipv4 log prefix \"Blocklist Bridge Dropped: \" drop
\t\tip6 saddr \@ipv6 log prefix \"Blocklist Bridge Dropped: \" drop
\t}
}\n";
    } else {
        print $tmp_bridge_or_nat "table inet $TABLE {\n";
	print $tmp_bridge_or_nat "$tmp_ipv4";
	print $tmp_bridge_or_nat "$tmp_ipv6";
        print $tmp_bridge_or_nat "\tchain prerouting {
\t\ttype filter hook prerouting priority 100; policy accept;
\t\tip saddr \@ipv4 log prefix \"Blocklist Prerouting Dropped: \" drop
\t\tip6 saddr \@ipv6 log prefix \"Blocklist Prerouting Dropped: \" drop
\t}
}\n";
    }
}
######## END addIpsToBlocklist ######

################## applyBlocklist ###################
####          Apply temp NFtable files          #####
#####################################################
sub applyBlocklist {
    if ( $bridge_nat_Option == 0 )
    {
        if ( $added_ipv4 > 0)
        {
	    `$nft -f $tmp_v4`;
            $message = "Added Blocklist for IPv4 to ruleset";
            logging($message);
        }
        if ( $added_ipv6 > 0)
        {
	    `$nft -f $tmp_v6`;
            $message = "Added Blocklist for IPv6 to ruleset";
            logging($message);
        }
    } else {
        if ( $added_ipv4 + $added_ipv6 > 0)
        {
	    `$nft -f $tmp_bridge_or_nat`;
            $message = "Added Bridge Blocklist for IPv4/IPv6 to ruleset";
            logging($message);
	}
    }
}
############### END applyBlocklist ######################

################## cleanup ###################
#### Cleanup: move tmp file to new place #####
##############################################
sub cleanup {
    for (1..$count) {
        $result = `$rm $tmpDir/Blocklist_$_ && echo "Deleted file $tmpDir/Blocklist_$_" || echo "Can\t delete file $tmpDir/Blocklist_$_"`;
    }
    $message = "We added $added (IPv4 = $added_ipv4, IPv6 = $added_ipv6), removed $removed, skipped $skipped Rules";
    logging($message);
}
############### END cleanup ######################

########### cleanupAll #################
#### Remove our Rules from nftables ####
#### and flush our ipset lists      ####
########################################

sub cleanupAll {
    my $returnCode;
    $returnCode = system("$nft list table ip blocklist > /dev/null 2> /dev/null");
    if ( $returnCode == 0 ) {
	`$nft delete table ip blocklist`;
    }
    $returnCode = system("$nft list table ip6 blocklist > /dev/null 2> /dev/null");
    if ( $returnCode == 0 ) {
	`$nft delete table ip6 blocklist`;
    }
    $returnCode = system("$nft list table bridge blocklist > /dev/null 2> /dev/null");
    if ( $returnCode == 0 ) {
	`$nft delete table bridge blocklist`;
    }
    $returnCode = system("$nft list table inet blocklist > /dev/null 2> /dev/null");
    if ( $returnCode == 0 ) {
	`$nft delete table inet blocklist`;
    }
}

########################################

###### log #######
## log $message ##
##################
sub logging {
    my ($message) = @_;

    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();

    open my $fh, ">>", $logFile
        or die "Can't open logfile: $!";
    $dateTime = sprintf("$months[$mon]  %02d %02d:%02d:%02d ", $mday,$hour,$min,$sec);
    print $fh "$dateTime $message\n";
    print "$message\n";

    close($fh);
}
#### end log #####

############## uniq ###############
## Make sure we wont             ##
## add/remove the same ip twice  ##
###################################

sub uniq { my %seen; grep !$seen{$_}++, @_ } # from http://stackoverflow.com/questions/13257095/remove-duplicate-values-for-a-key-in-hash

#### end uniq ####

######### EOF ###########
