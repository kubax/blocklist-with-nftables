#!/usr/bin/env perl
use v5.32;
use strict;
use warnings;

use Fcntl qw(:flock);
use File::Spec;
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use Getopt::Long qw(GetOptions);
use HTTP::Tiny;
use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop);
use Math::BigInt;

#################################################################
###### Script to parse blocklists. Block new IPs and       ######
###### remove deleted entries by rebuilding nftables sets. ######
###### Multiple lists possible. IPv4 and IPv6 supported.   ######
#################################################################

## config ##
my @list_url;
my $log_file;
my $white_list;
my $black_list;
my $version = '1.2.1';

## binaries ##
$ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
my $nft = $ENV{NFT} // "nft";

my $table = "blocklist";
my $mode  = "input";

my %stats = (
    added      => 0,
    removed    => 0,
    skipped    => 0,
    added_ipv4 => 0,
    added_ipv6 => 0,
);

open my $self, '<', $0 or die "Couldn't open self: $!";
flock $self, LOCK_EX | LOCK_NB or die "This script is already running\n";

init();

sub init {
    my $help;
    my $cleanup;
    my $bridge;
    my $nat;

    GetOptions(
        'h|help'    => \$help,
        'c|cleanup' => \$cleanup,
        'b|bridge'  => \$bridge,
        'n|nat'     => \$nat,
    ) or usage(1);

    usage(0) if $help;
    die "Options --bridge and --nat are mutually exclusive\n" if $bridge && $nat;

    cleanup_all() if $cleanup;
    exit 0 if $cleanup;

    $mode = "bridge" if $bridge;
    $mode = "nat"    if $nat;

    # determine the config file path
    my ($volume, $directories, $script_name) = File::Spec->splitpath(File::Spec->rel2abs(__FILE__));
    my $default_config = File::Spec->catfile($directories, 'blocklist.conf');
    my $installed_config = '/etc/blocklist/blocklist.conf';
    my $config_file = $ENV{BLOCKLIST_CONFIG} // $default_config;

    unless (-e $config_file) {
        $config_file = $installed_config if -e $installed_config;
    }

    die "Config file not found: $config_file" unless -e $config_file;

    my %c;
    open my $cfg, '<', $config_file or die "Could not open config file $config_file: $!";
    while (my $line = <$cfg>) {
        chomp $line;
        $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            next if $line =~ /^\s*[#;]/;
            $line =~ s/\s*[#;].*$//;    # strip inline comments (# or ;)
        next if $line =~ /^\s*$/;
        if ($line =~ /^([^=\s]+)\s*=\s*(.+)$/) {
            my ($k, $v) = ($1, $2);
            if ($k eq 'list_url') {
                push @{ $c{list_url} }, $v;
            } else {
                $c{$k} = $v;
            }
        }
    }
    close $cfg;

    if (!exists $c{list_url} || !exists $c{log_file} || !exists $c{white_list} || !exists $c{black_list}) {
        die "Invalid config file: missing required configuration keys";
    }

    @list_url   = @{ $c{list_url} };
    $log_file   = $c{log_file};
    $white_list = $c{white_list};
    $black_list = $c{black_list};

    ensure_log_file_exists();
    ensure_list_files_exist();

    # print the version and config for debugging
    print "blocklist-with-nftables version $version\n";
    print "Using the following configuration:\n";
    print "List URLs:\n";
    print "  - $_\n" for @list_url;
    print "Log file: $log_file\n";
    print "Whitelist file: $white_list\n";
    print "Blacklist file: $black_list\n\n";

    main();
}

sub ensure_log_file_exists {
    return unless defined $log_file && length $log_file;

    my ($volume, $directories, $filename) = File::Spec->splitpath($log_file);
    if ($directories && !-d $directories) {
        make_path($directories) or die "Could not create log directory $directories: $!";
    }

    unless (-e $log_file) {
        open my $fh, '>>', $log_file or die "Could not create log file $log_file: $!";
        close $fh or die "Could not close log file $log_file: $!";
    }
}

sub ensure_list_files_exist {
    for my $path ($white_list, $black_list) {
        die "Missing required file: $path\n" unless defined $path && length $path;
        die "Required file not found: $path\n" unless -e $path;
        die "Required file is not readable: $path\n" unless -r $path;
    }
}

sub usage {
    my ($exit_code) = @_;
    print STDERR <<'EOF';
blocklist-with-nftables

This script downloads and parses text files with IPs and blocks them.
Just run ./blocklist.pl

If you want to clean everything up run:
./blocklist.pl -c

If you want to block IPs on the bridge table run:
./blocklist.pl -b

If you want to block IPs on inet table prerouting to protect NAT run:
./blocklist.pl -n

EOF
    exit $exit_code;
}

sub main {
    logging("Starting blocklist refresh");
    logging("Removing Blocklist Tables");
    cleanup_all();

    logging("Generating Whitelist Array");
    my @whitelist = read_list_file($white_list);

    logging("Generating Blacklist Array");
    my @blacklist = read_list_file($black_list);

    logging("Generating Blocklist Array");
    my @blocklist = download_blocklists(@list_url);

    logging("Adding IPs to Blocklist");
    my ($ipv4, $ipv6) = collect_blocklist_entries(\@blocklist, \@blacklist, \@whitelist);

    logging("Adding Blocklist to ruleset");
    apply_blocklist($ipv4, $ipv6);

    logging("Starting Cleanup");
    logging(
        "We added $stats{added} (IPv4 = $stats{added_ipv4}, IPv6 = $stats{added_ipv6}), "
        . "removed $stats{removed}, skipped $stats{skipped} Rules"
    );

    exit 0;
}

sub read_list_file {
    my ($path) = @_;
    open my $fh, '<', $path or die "Could not open $path: $!";
    my @lines;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';
        next if $line =~ /^\s*[#;]/;   # skip full-line comments starting with # or ;
        $line =~ s/\s*[#;].*$//;       # strip inline comments (# or ;)
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';
        push @lines, $line;
    }
    # print the number of entries read for verification
    logging("Read " . scalar(@lines) . " entries from $path");
    close $fh or die "Could not close $path: $!";
    return @lines;
}

sub download_blocklists {
    my (@urls) = @_;
    my $http = HTTP::Tiny->new(timeout => 60);
    my @entries;

    for my $url (@urls) {
        my $response = $http->get($url);
        die "Can not download $url: $response->{status} $response->{reason}\n"
            unless $response->{success};

        for my $line (split /\R/, $response->{content}) {
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            next if $line =~ /^\s*[#;]/;   # skip commented lines starting with # or ;
            $line =~ s/\s*[#;].*$//;       # strip inline comments (# or ;)
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            push @entries, $line;
        }
        logging("Downloaded blocklist from $url");
    }

    return @entries;
}

sub collect_blocklist_entries {
    my ($blocklist, $blacklist, $whitelist) = @_;
    # build whitelist structures for containment checks
    my @wl = @$whitelist;
    my (@wl4_singles, @wl4_cidrs, @wl6_singles, @wl6_cidrs);
    for my $w (@wl) {
        next unless defined $w;
        $w =~ s/^\s+|\s+$//g;
        next if $w eq '';
        if ($w =~ /\//) {
            if (is_ipv4($w)) { push @wl4_cidrs, $w } elsif (is_ipv6($w)) { push @wl6_cidrs, $w }
        } else {
            if (is_ipv4($w)) { push @wl4_singles, $w } elsif (is_ipv6($w)) { push @wl6_singles, $w }
        }
    }

    my @wl4_cidr_structs = map { my ($s,$e)=cidr_to_range($_); { start => $s, end => $e } } @wl4_cidrs;
    my @wl6_cidr_structs = map { my ($s,$e)=cidr_to_range($_); { start => $s, end => $e } } @wl6_cidrs;

    my @raw4;
    my @raw6;

    for my $line (uniq(@$blacklist, @$blocklist)) {
        next unless defined $line;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';

        # skip exact whitelist matches quickly
        if (grep { $_ eq $line } @wl4_singles, @wl6_singles) {
            $stats{skipped}++;
            next;
        }

        if (is_ipv4($line)) {
            my $packed = pack_ip($line);
            if (ip_in_any_ranges($packed, @wl4_cidr_structs)) {
                $stats{skipped}++;
                next;
            }
            push @raw4, $line;
        } elsif (is_ipv6($line)) {
            my $packed = pack_ip($line);
            if (ip_in_any_ranges($packed, @wl6_cidr_structs)) {
                $stats{skipped}++;
                next;
            }
            push @raw6, $line;
        } else {
            $stats{skipped}++;
        }
    }

    # normalize: remove duplicates, remove single IPs contained in CIDRs,
    # and remove CIDRs that are fully contained in other CIDRs or that would
    # block whitelist single IPs.
    my @ipv4 = normalize_entries(\@raw4, \@wl4_singles, \@wl4_cidrs, 4);
    my @ipv6 = normalize_entries(\@raw6, \@wl6_singles, \@wl6_cidrs, 6);

    $stats{added_ipv4} = scalar @ipv4;
    $stats{added_ipv6} = scalar @ipv6;
    $stats{added} = $stats{added_ipv4} + $stats{added_ipv6};

    return (\@ipv4, \@ipv6);
}

sub normalize_entries {
    my ($entries_ref, $wl_singles_ref, $wl_cidrs_ref, $family) = @_;
    my @entries = @$entries_ref;
    my %seen;
    my (@singles, @cidrs);

    # separate singles and cidrs, dedupe exact strings
    for my $e (@entries) {
        next unless defined $e;
        $e =~ s/^\s+|\s+$//g;
        next if $e eq '';
        next if $seen{$e}++;
        if ($e =~ /\//) { push @cidrs, $e } else { push @singles, $e }
    }

    # memoize packed IPs for whitelist singles and input singles
    my %pack_cache;
    my @wl_packed = sort { $a cmp $b } grep { defined } map { $pack_cache{$_} //= pack_ip($_) } grep { defined && length } @$wl_singles_ref;

    # build cidr structs with packed ranges
    my @cidr_structs;
    for my $c (@cidrs) {
        my ($start, $end) = cidr_to_range($c);
        next unless defined $start;
        push @cidr_structs, { cidr => $c, start => $start, end => $end };
    }

    # sort cidrs by start to allow linear scan for containment and overlap
    @cidr_structs = sort { $a->{start} cmp $b->{start} } @cidr_structs;

    # remove cidrs that would block any whitelist single or whitelist cidr using binary search
    for my $c (@cidr_structs) {
        next unless @wl_packed || @{$wl_cidrs_ref};
        my $skip = 0;
        if (@wl_packed) {
            my $idx = lower_bound_pack(\@wl_packed, $c->{start});
            for my $j ($idx-1, $idx) {
                next if $j < 0 || $j > $#{\@wl_packed};
                if (ip_in_range($wl_packed[$j], $c->{start}, $c->{end})) { $skip = 1; last }
            }
        }
        if (!$skip && @{$wl_cidrs_ref}) {
            my @wl_ranges = map { my ($s,$e)=cidr_to_range($_); { start => $s, end => $e } } @{$wl_cidrs_ref};
            if (range_overlaps_any($c->{start}, $c->{end}, @wl_ranges)) {
                $skip = 1;
            }
        }
        $c->{skip} = 1 if $skip;
    }

    # linear sweep to remove cidrs contained in previous (non-skipped) cidr
    my @kept;
    for my $c (@cidr_structs) {
        next if $c->{skip};
        if (@kept) {
            my $last = $kept[-1];
            # if current is fully contained in last, skip it
            if ($c->{start} ge $last->{start} && $c->{end} le $last->{end}) {
                next;
            }
            # if overlaps partially, expand last end to cover both to avoid conflicts
            if ($c->{start} le $last->{end}) {
                $last->{end} = $c->{end} if $c->{end} gt $last->{end};
                # we also mark current as merged so we won't output it
                $c->{skip} = 1;
                next;
            }
        }
        push @kept, $c;
    }

    # produce final cidr list by converting merged/kept ranges into minimal CIDRs
    my @final_cidrs;
    my @kept_ranges;
    for my $k (@kept) {
        next if $k->{skip};
        push @kept_ranges, { start => $k->{start}, end => $k->{end} };
        push @final_cidrs, range_to_cidrs($k->{start}, $k->{end});
    }

    # remove singles that fall into any remaining cidr using binary search
    my @final_singles;
    for my $s (@singles) {
        my $sp = $pack_cache{$s} //= pack_ip($s);
        next unless defined $sp;
        my $in = 0;
        # binary search on kept_ranges by start
        my $idx = lower_bound_ranges(\@kept_ranges, $sp);
        for my $j ($idx-1, $idx) {
            next if $j < 0 || $j > $#{\@kept_ranges};
            if (ip_in_range($sp, $kept_ranges[$j]{start}, $kept_ranges[$j]{end})) { $in = 1; last }
        }
        push @final_singles, $s unless $in;
    }

    return (@final_cidrs, @final_singles);
}

sub pack_ip {
    my ($ip) = @_;
    return undef unless defined $ip && length $ip;
    my $p = inet_pton(AF_INET, $ip);
    return $p if defined $p;
    return inet_pton(AF_INET6, $ip);
}

sub cidr_to_range {
    my ($cidr) = @_;
    return unless $cidr =~ m{^([^/]+)/(\d+)$};
    my ($ip, $prefix) = ($1, $2);
    my $p = pack_ip($ip);
    return unless defined $p;
    my $len = length $p;    # 4 or 16

    # build mask bytes
    my @mask;
    my $bits = $prefix;
    for my $i (1..$len) {
        if ($bits >= 8) { push @mask, 0xFF; $bits -= 8 }
        elsif ($bits <= 0) { push @mask, 0x00 }
        else { push @mask, ((0xFF << (8 - $bits)) & 0xFF); $bits = 0 }
    }

    # compute network base (start) and end
    my $start = '';
    my $end = '';
    for my $i (0..$len-1) {
        my $b = ord(substr($p, $i, 1));
        my $m = $mask[$i];
        my $nb = $b & $m;
        my $eb = $nb | (~$m & 0xFF);
        $start .= chr($nb);
        $end   .= chr($eb);
    }

    return ($start, $end);
}

sub ip_in_range {
    my ($ip_packed, $start, $end) = @_;
    return 0 unless defined $ip_packed && defined $start && defined $end;
    return ($ip_packed ge $start && $ip_packed le $end) ? 1 : 0;
}

sub ip_in_any_ranges {
    my ($ip_packed, @ranges) = @_;
    return 0 unless defined $ip_packed;
    for my $range (@ranges) {
        next unless defined $range->{start} && defined $range->{end};
        return 1 if ip_in_range($ip_packed, $range->{start}, $range->{end});
    }
    return 0;
}

sub range_overlaps_any {
    my ($start, $end, @ranges) = @_;
    return 0 unless defined $start && defined $end;
    for my $range (@ranges) {
        next unless defined $range->{start} && defined $range->{end};
        return 1 if !($end lt $range->{start} || $range->{end} lt $start);
    }
    return 0;
}

sub cidr_contains {
    my ($outer, $inner) = @_; # both are {start =>..., end=>...}
    return 0 unless defined $outer && defined $inner;
    return ($inner->{start} ge $outer->{start} && $inner->{end} le $outer->{end}) ? 1 : 0;
}

# lower_bound for packed strings array: first index with value >= target
sub lower_bound_pack {
    my ($arr_ref, $target) = @_;
    my $lo = 0;
    my $hi = scalar(@$arr_ref);
    while ($lo < $hi) {
        my $mid = int(($lo + $hi) / 2);
        if ($arr_ref->[$mid] lt $target) { $lo = $mid + 1 } else { $hi = $mid }
    }
    return $lo;
}

# lower_bound for ranges array (each element {start=>..., end=>...}), compare by start
sub lower_bound_ranges {
    my ($arr_ref, $target) = @_;
    my $lo = 0;
    my $hi = scalar(@$arr_ref);
    while ($lo < $hi) {
        my $mid = int(($lo + $hi) / 2);
        if ($arr_ref->[$mid]{start} lt $target) { $lo = $mid + 1 } else { $hi = $mid }
    }
    return $lo;
}

sub packed_to_bigint {
    my ($packed) = @_;
    return unless defined $packed;
    my $hex = unpack('H*', $packed);
    return Math::BigInt->from_hex('0x' . $hex);
}

sub bigint_to_packed {
    my ($bi, $len) = @_;
    return unless defined $bi;
    my $hex = $bi->as_hex(); # '0x...'
    $hex =~ s/^0x//i;
    $hex = '0' . $hex unless length($hex) % 2 == 0;
    my $need = $len * 2;
    $hex = ('0' x ($need - length($hex))) . $hex if length($hex) < $need;
    return pack('H*', $hex);
}

sub range_to_cidrs {
    my ($start_packed, $end_packed) = @_;
    my $len = length $start_packed;
    my @cidrs;

    if ($len == 4) {
        # IPv4: use native integers for speed and correctness
        my $s = unpack('N', $start_packed);
        my $e = unpack('N', $end_packed);
        while ($s <= $e) {
            # largest block aligned at s
            my $tmp = $s;
            my $tz = 0;
            while (($tmp & 1) == 0 && $tz < 32) { $tmp >>= 1; $tz++; }
            my $max_block = 1 << $tz;
            # reduce block if it exceeds range
            while ($s + $max_block - 1 > $e) {
                $max_block >>= 1;
            }
            my $prefix = 32 - (int(log($max_block)/log(2)));
            my $ip_text = sprintf('%d.%d.%d.%d', ($s>>24)&0xFF, ($s>>16)&0xFF, ($s>>8)&0xFF, $s&0xFF);
            push @cidrs, "$ip_text/$prefix";
            $s += $max_block;
        }
        return @cidrs;
    }

    # IPv6: BigInt path
    my $maxbits = $len * 8;
    my $start_bi = packed_to_bigint($start_packed);
    my $end_bi = packed_to_bigint($end_packed);

    while ($start_bi <= $end_bi) {
        # find largest block aligned at start
        my $max_pref = 0;
        for (my $pref = 0; $pref <= $maxbits; $pref++) {
            my $block = Math::BigInt->new(2)->bpow($maxbits - $pref);
            # alignment check: start_bi % block == 0
            my $mod = $start_bi->copy()->bmod($block);
            last if $mod->is_pos();
            $max_pref = $pref;
        }
        # adjust prefix so block does not exceed end
        while (1) {
            my $block = Math::BigInt->new(2)->bpow($maxbits - $max_pref);
            my $block_end = $start_bi->copy()->badd($block)->bdec();
            last if $block_end <= $end_bi;
            $max_pref++;
        }

        # produce cidr for start_bi with prefix max_pref
        my $packed = bigint_to_packed($start_bi, $len);
        my $ip_text = inet_ntop(AF_INET6, $packed);
        push @cidrs, "$ip_text/$max_pref";

        # advance start_bi by block size
        my $advance = Math::BigInt->new(2)->bpow($maxbits - $max_pref);
        $start_bi = $start_bi->copy()->badd($advance);
    }

    return @cidrs;
}

sub is_ipv4 {
    my ($value) = @_;
    return 0 unless defined $value && length $value;
    if ($value =~ m{^([^/]+)/(\d+)$}) {
        $value = $1;
    }
    return defined inet_pton(AF_INET, $value);
}

sub is_ipv6 {
    my ($value) = @_;
    return 0 unless defined $value && length $value;
    if ($value =~ m{^([^/]+)/(\d+)$}) {
        $value = $1;
    }
    return defined inet_pton(AF_INET6, $value);
}

sub render_set {
    my ($name, $type, $entries) = @_;
    my $rules = "\tset $name {\n"
        . "\t\ttype $type\n"
        . "\t\tflags interval\n"
        . "\t\telements = {\n";

    $rules .= join "", map { "\t\t\t$_,\n" } @$entries;
    $rules .= "\t\t}\n\t}\n";
    return $rules;
}

sub input_ruleset {
    my ($family, $set_name, $set_type, $field, $entries) = @_;
    return "table $family $table {\n"
        . render_set($set_name, $set_type, $entries)
        . "\tchain input {\n"
        . "\t\ttype filter hook input priority filter; policy accept;\n"
        . "\t\t$field \@$set_name log prefix \"Blocklist Dropped: \" drop\n"
        . "\t}\n"
        . "}\n";
}

sub bridge_or_nat_ruleset {
    my ($family, $prefix, $ipv4, $ipv6) = @_;
    return "table $family $table {\n"
        . render_set("ipv4", "ipv4_addr", $ipv4)
        . render_set("ipv6", "ipv6_addr", $ipv6)
        . "\tchain prerouting {\n"
        . "\t\ttype filter hook prerouting priority filter; policy accept;\n"
        . "\t\tip saddr \@ipv4 log prefix \"$prefix\" drop\n"
        . "\t\tip6 saddr \@ipv6 log prefix \"$prefix\" drop\n"
        . "\t}\n"
        . "}\n";
}

sub apply_blocklist {
    my ($ipv4, $ipv6) = @_;

    if ($mode eq "input") {
        if (@$ipv4) {
            apply_ruleset(input_ruleset("ip", "ipv4", "ipv4_addr", "ip saddr", $ipv4));
            logging("Added Blocklist for IPv4 to ruleset");
        }
        if (@$ipv6) {
            apply_ruleset(input_ruleset("ip6", "ipv6", "ipv6_addr", "ip6 saddr", $ipv6));
            logging("Added Blocklist for IPv6 to ruleset");
        }
        return;
    }

    return unless @$ipv4 || @$ipv6;

    my $family = $mode eq "bridge" ? "bridge" : "inet";
    my $prefix = $mode eq "bridge"
        ? "Blocklist Bridge Dropped: "
        : "Blocklist Prerouting Dropped: ";

    apply_ruleset(bridge_or_nat_ruleset($family, $prefix, $ipv4, $ipv6));
    logging("Added Bridge or NAT Blocklist for IPv4/IPv6 to ruleset");
}

sub apply_ruleset {
    my ($ruleset) = @_;
    my ($fh, $filename) = tempfile();
    print {$fh} $ruleset;
    close $fh or die "Could not close temp ruleset $filename: $!";
    run_nft("-f", $filename);
    unlink $filename or warn "Could not delete temp ruleset $filename: $!";
}

sub cleanup_all {
    for my $family (qw(ip ip6 bridge inet)) {
        next unless nft_table_exists($family);
        run_nft("delete", "table", $family, $table);
    }
}

sub nft_table_exists {
    my ($family) = @_;
    return run_command_quiet($nft, "list", "table", $family, $table);
}

sub run_nft {
    my (@args) = @_;
    system($nft, @args) == 0
        or die "nft @args failed with exit code " . ($? >> 8) . "\n";
}

sub run_command_quiet {
    my (@command) = @_;

    my $pid = fork();
    die "Could not fork for @command: $!" unless defined $pid;

    if ($pid == 0) {
        open STDOUT, '>', File::Spec->devnull
            or die "Could not redirect STDOUT to null device: $!";
        open STDERR, '>', File::Spec->devnull
            or die "Could not redirect STDERR to null device: $!";
        exec @command;
        exit 127;
    }

    waitpid $pid, 0;
    return $? == 0;
}

sub logging {
    my ($message) = @_;
    my ($sec, $min, $hour, $mday, $mon) = localtime();
    my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $date_time = sprintf("%s  %02d %02d:%02d:%02d", $months[$mon], $mday, $hour, $min, $sec);

    open my $fh, '>>', $log_file or die "Can't open logfile $log_file: $!";
    print {$fh} "$date_time $message\n";
    print "$message\n";
}

sub uniq {
    my %seen;
    return grep { !$seen{$_}++ } @_;
}
