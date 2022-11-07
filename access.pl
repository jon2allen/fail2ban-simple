#!/usr/bin/perl

# -------------------------------------------------------------------------------------------------------
# 1. Ban abusing ip addresses detected by PAM in file '/var/log/secure file"
#    Ex. "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root"
# 2. Check duplication by 'iptables -L' command
# -------------------------------------------------------------------------------------------------------


MAIN: {
    # my @lines = `/usr/bin/tail -20000 /var/log/secure`;
    my @lines = `cat /var/log/secure`;
   
    foreach my $line (@lines) {
        # PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
        if ($line =~ /PAM\s+\d+\s+more authentication failures.+rhost=([\d\.]+).+user=(\S+)/) {
            my ($ip, $uid) = ($1, $2);
            if (! defined $intrusion->{$ip}) {
                $intrusion->{$ip} = [];
            }
            push @{$intrusion->{$ip}}, $uid;
        }

        #  Accepted publickey for ec2-user from 74.96.73.46

        if ($line =~ /Accepted publickey for (\S+) from ([\d\.]+)/) {
            my $user = $1;
            my $ip = $2;
            print "valid user found: $user \n";
            print "valid ip found:  $ip \n"


        }
        # Invalid user support from 205.185.125.129 port 57184
        
        # Failed password for invalid user ubnt from 167.114.129.42 port 53685 ssh2
        if ($line =~/Invalid user (\S+) from ([\d\.]+)/) {
            my $user = $1;
            my $ip = $2;
            print "invalid user is $user \n";
            print "invalid ip is $ip \n"

        }
    }

    foreach my $ip (keys %{$intrusion}) {
        if (@{$intrusion->{$ip}} >= 1) {
            # print "$ip: @{$intrusion->{$ip}}\n";
            print "$ip is suspecious\n";
            
        }
    }
    
    foreach my $ip (keys %{$intrusion2}) {
        if (@{$intrusion2->{$ip}} >= 2) {
            print "$ip: @{$intrusion2->{$ip}}\n";
            print "$ip is suspecious\n";
            
        }
    }

}
