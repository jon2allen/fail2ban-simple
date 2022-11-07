#!/usr/bin/perl

# -------------------------------------------------------------------------------------------------------
# 1. Ban abusing ip addresses detected by did not issue MAIL/EXPN/VRFY/ETRN in file '/var/log/maillog file"
# 2. Check duplication by 'iptables -L' command
# **** sendmail *** port 25
# -------------------------------------------------------------------------------------------------------

my @iptables = `/sbin/iptables -L -n`;
my $prot_ip = `cat .nobanip`;

sub ban_ip($)
{
    my ($ip) = @_;

    my $found = 0;
    if ($ip =~ /$prot_ip/ && (length($prot_ip) > 0) ) {
            print "$ip is protected \n";
            return;
    }
    foreach my $line (@iptables) {
        if ($line =~ /$ip/ && $line =~ /REJECT/ && $line =~ /dpt:25/) {
            $found = 1; last;
        }
    }

    foreach my $line (@iptables) {
        if ($line =~ /$ip/ && $line =~ /REJECT/ && $line =~ /dpt:465/) {
            $found = 1; last;
        }
    }

    if ($found) { # Don't register duplicated ip block
        print "$ip is already in DROP list\n";
        return;
    }
   
    # my $cmd = "/sbin/iptables -A INPUT -s $ip -p tcp --destination-port 22 -j REJECT";
    my $cmd = "/sbin/iptables -A INPUT -s $ip -p tcp --destination-port 25 -j REJECT";
    `$cmd`;
    print "+OK FAIL2BAN $ip\n";
    my $cmd = "/sbin/iptables -A INPUT -s $ip -p tcp --destination-port 465 -j REJECT";
    `$cmd`;
    print "+OK fail2ban port 465 \n";
}

MAIN: {
    # my @lines = `/usr/bin/tail -20000 /var/log/secure`;
    my @lines = `cat /var/log/maillog`;
    my $intrusion = {};
    my $intrusion2 = {};
    my $ban_total = 0;
    my $lent = length($prot_ip);
    print("Protected IP: $prot_ip  Len: $lent \n");
    foreach my $line (@lines) {
        # PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
    #    if ($line =~ /PAM\s+\d+\s+more authentication failures.+rhost=([\d\.]+).+user=(\S+)/) {
    #        my ($ip, $uid) = ($1, $2);
    #        if (! defined $intrusion->{$ip}) {
    #            $intrusion->{$ip} = [];
    #        }
    #        push @{$intrusion->{$ip}}, $uid;
    #    }

        # Invalid user support from 205.185.125.129 port 57184
        
        # Failed password for invalid user ubnt from 167.114.129.42 port 53685 ssh2
        if ($line =~/(\d+\.\d+\.\d+\.\d+).+did not issue MAIL\/EXPN\/VRFY\/ETRN during connection/){
            my $ip = $1;
            # print "line: $line";
            if (! defined $intrusion2->{$ip}) {
                $intrusion2->{$ip} = [];
            }
            push @{$intrusion2->{$ip}}, $ip;
        }
    }

    #foreach my $ip (keys %{$intrusion}) {
    #    if (@{$intrusion->{$ip}} >= 1) {
    #        # print "$ip: @{$intrusion->{$ip}}\n";
    #        print "$ip is suspecious\n";
    #        #ban_ip($ip);
    #    }
    #}
    
    foreach my $ip (keys %{$intrusion2}) {
        if (@{$intrusion2->{$ip}} >= 2) {
            print "$ip: @{$intrusion2->{$ip}}\n";
            print "$ip is suspecious\n";
            ban_ip($ip)
        }
    }
}
