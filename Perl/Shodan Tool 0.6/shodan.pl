#!usr/bin/perl
#Shodan Tool 0.6
#(C) Doddy Hackman 2015
#Based on : https://developer.shodan.io/api
#ppm install http://www.eekboek.nl/dl/ppms/Crypt-SSLeay.ppd
#ppm install http://www.bribes.org/perl/ppm/JSON.ppd

use LWP::UserAgent;
use JSON;
use Getopt::Long;
use Color::Output;
Color::Output::Init;
use IO::Socket;

my $nave = LWP::UserAgent->new( ssl_opts => { verify_hostname => 1 } );
$nave->agent(
"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0"
);
$nave->timeout(5);

my $api_key = "LY10TuYViggY3GXRzLOUxdp6Kk3Lu9sa";

GetOptions(
    "ip=s"           => \$ip,
    "count=s"        => \$count,
    "search=s"       => \$search,
    "query"          => \$query,
    "query_search=s" => \$query_search,
    "query_tags"     => \$query_tags,
    "services"       => \$services,
    "resolve=s"      => \$resolve,
    "reverse=s"      => \$reverse,
    "myip"           => \$myip,
    "api_info"       => \$api_info
);

head();

if ( $ip ne "" ) {
    if ( $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ ) {
        print by_ip($ip);
    }
    else {
        my $get = gethostbyname($ip);
        my $ip  = inet_ntoa($get);
        by_ip($ip);
    }
}
elsif ( $count ne "" ) {
    by_count($count);
}
elsif ( $search ne "" ) {
    by_search($search);
}
elsif ( $query ne "" ) {
    by_query();
}
elsif ($query_search) {
    by_query_search($query_search);
}
elsif ($query_tags) {

    by_query_tags($query_tags);

}
elsif ( $services ne "" ) {
    list_services();
}
elsif ( $resolve ne "" ) {
    resolve($resolve);
}
elsif ( $reverse ne "" ) {
    reverse_now($reverse);
}
elsif ( $myip ne "" ) {
    my_ip();
}
elsif ( $api_info ne "" ) {
    api_info();
}
else {
    sintax();
}

copyright();

# Functions

sub by_query_tags {

    printear_titulo("\n[+] Listening the most popular tags  ...\n\n");

    my $code =
      toma( "https://api.shodan.io/shodan/query/tags?key=" . $api_key );

    $resultado = JSON->new->decode($code);

    my $total = $resultado->{'total'};

    if ( $total ne "" ) {
        printear("[+] Total : ");
        print $total. "\n\n";
    }
    else {
        printear("[-] WTF !");
    }

    my $i = 0;

    my @encontrados = @{ $resultado->{'matches'} };
    foreach my $encontrado (@encontrados) {
        my $value = $encontrado->{"value"};
        my $count = $encontrado->{"count"};

        $i++;
        print "-------------------------------------\n\n";
        if ( $value ne "" ) {
            printear("[+] Value : ");
            print $value. "\n";
        }

        if ( $count ne "" ) {
            printear("[+] Count : ");
            print $count. "\n";
        }

        print "\n-------------------------------------\n";

        if ( $i % 5 == 0 ) {
            printear("\n[+] Press enter to show more\n");
            <STDIN>;
        }

    }

}

sub by_query_search {

    my $query = $_[0];

    printear_titulo(
        "\n[+] Searching in the directory of saved search queries ...\n\n");

    my $code =
      toma( "https://api.shodan.io/shodan/query/search?key="
          . $api_key
          . "&query="
          . $query );

    $resultado = JSON->new->decode($code);

    my $total = $resultado->{'total'};

    if ( $total ne "" ) {
        printear("[+] Total : ");
        print $total. "\n\n";
    }
    else {
        printear("[-] WTF !");
    }

    my $i = 0;

    my @encontrados = @{ $resultado->{'matches'} };
    foreach my $encontrado (@encontrados) {
        $i++;
        print "-------------------------------------\n\n";
        my $votes       = $encontrado->{"votes"};
        my $description = $encontrado->{"description"};
        my $title       = $encontrados->{"title"};
        my $timestamp   = $encontrados->{"timestamp"};
        my $query       = $encontrados->{"query"};

        if ( $votes ne "" ) {
            printear("[+] Votes : ");
            print $votes. "\n";
        }

        if ( $description ne "" ) {
            printear("[+] Description : ");
            print $description. "\n\n";
        }

        if ( $title ne "" ) {
            printear("[+] Title : ");
            print $title. "\n";
        }

        if ( $timestamp ne "" ) {
            printear("[+] Timestamp : ");
            print $timestamp. "\n";
        }

        if ( $query ne "" ) {
            printear("[+] Query : ");
            print $query. "\n";
        }

        printear("[+] Tags : ");
        my @tags = @{ $encontrado->{'tags'} };
        foreach my $tag (@tags) {
            print $tag. "\t";
        }
        print "\n";

        print "\n-------------------------------------\n";

        if ( $i % 5 == 0 ) {
            printear("\n[+] Press enter to show more\n");
            <STDIN>;
        }

    }

}

sub by_query {

    printear_titulo("\n[+] Listening the saved search queries ...\n\n");

    my $code = toma( "https://api.shodan.io/shodan/query?key=" . $api_key );
    $resultado = JSON->new->decode($code);

    my $total = $resultado->{'total'};

    if ( $total ne "" ) {
        printear("[+] Total : ");
        print $total. "\n\n";
    }
    else {
        printear("[-] WTF !");
    }

    my $i = 0;

    my @encontrados = @{ $resultado->{'matches'} };
    foreach my $encontrado (@encontrados) {
        $i++;
        print "-------------------------------------\n\n";
        my $votes       = $encontrado->{"votes"};
        my $description = $encontrado->{"description"};
        my $title       = $encontrados->{"title"};
        my $timestamp   = $encontrados->{"timestamp"};
        my $query       = $encontrados->{"query"};

        if ( $votes ne "" ) {
            printear("[+] Votes : ");
            print $votes. "\n";
        }

        if ( $description ne "" ) {
            printear("[+] Description : ");
            print $description. "\n\n";
        }

        if ( $title ne "" ) {
            printear("[+] Title : ");
            print $title. "\n";
        }

        if ( $timestamp ne "" ) {
            printear("[+] Timestamp : ");
            print $timestamp. "\n";
        }

        if ( $query ne "" ) {
            printear("[+] Query : ");
            print $query. "\n";
        }

        printear("[+] Tags : ");
        my @tags = @{ $encontrado->{'tags'} };
        foreach my $tag (@tags) {
            print $tag. "\t";
        }
        print "\n";

        print "\n-------------------------------------\n";

        if ( $i % 5 == 0 ) {
            printear("\n[+] Press enter to show more\n");
            <STDIN>;
        }

    }

}

sub list_services {

    printear_titulo("\n[+] Listening all services that Shodan crawls ...\n\n");

    my $code = toma( "https://api.shodan.io/shodan/services?key=" . $api_key );
    if ( $code ne "" ) {
        my $i = 0;
        while ( $code =~ /"(.*?)": "(.*?)"/migs ) {
            $i++;
            my $port = $1;
            my $name = $2;
            printear("[+] Port : ");
            print $port. "\n";
            printear("[+] Name : ");
            print $name. "\n\n";

            if ( $i % 20 == 0 ) {
                printear("\n[+] Press enter to show more\n");
                <STDIN>;
            }

        }
    }
    else {
        print "[-] WTF !" . "\n";
    }

}

sub resolve {

    my $hostnames = $_[0];

    printear_titulo("\n[+] Working in DNS Lookup ...\n\n");

    my $code =
      toma( "https://api.shodan.io/dns/resolve?hostnames="
          . $hostnames . "&key="
          . $api_key );
    if ( $code ne "" ) {
        while ( $code =~ /"(.*?)": "(.*?)"/migs ) {
            my $host = $1;
            my $ip   = $2;
            printear("[+] Hostname : ");
            print $host. "\n";
            printear("[+] IP : ");
            print $ip. "\n";
        }
    }
    else {
        printear( "[-] WTF !" . "\n" );
    }

}

sub reverse_now {

    $ips = $_[0];

    printear_titulo("\n[+] Working in Reverse DNS Lookup ...\n\n");

    my $code = toma(
        "https://api.shodan.io/dns/reverse?ips=" . $ips . "&key=" . $api_key );
    if ( $code ne "" ) {
        while ( $code =~ /"(.*?)": \["(.*?)"\]/migs ) {
            my $ip   = $1;
            my $host = $2;
            printear("[+] IP : ");
            print $ip. "\n";
            printear("[+] Hostname : ");
            print $host. "\n";
        }
    }
    else {
        printear( "[-] WTF !" . "\n" );
    }
}

sub my_ip {
    printear_titulo("\n[+] Getting your IP ...\n\n");
    my $code = toma( "https://api.shodan.io/tools/myip?key=" . $api_key );
    if ( $code =~ /"(.*)"/ ) {
        my $ip = $1;
        printear("[+] IP : ");
        print $ip. "\n";
    }
    else {
        printear( "[-] WTF !" . "\n" );
    }
}

sub api_info {

    printear_titulo("\n[+] Getting your API Info ...\n\n");

    my $code = toma( "https://api.shodan.io/api-info?key=" . $api_key );

    $resultado = JSON->new->decode($code);
    my $unlock_left = $resultado->{"unlocked_left"};
    my $telnet      = $resultado->{"telnet"};
    my $plan        = $resultado->{"plan"};
    my $http        = $resultado->{"https"};
    my $unlocked    = $resultado->{"unlocked"};

    if ( $unlock_left ne "" ) {
        printear("[+] Unlocked left : ");
        print $unlock_left. "\n";
    }
    if ( $telnet ne "" ) {
        printear("[+] Telnet : ");
        print $telnet. "\n";
    }
    if ( $plan ne "" ) {
        printear("[+] Plan : ");
        print $plan. "\n";
    }
    if ( $http ne "" ) {
        printear("[+] HTTPS : ");
        print $http. "\n";
    }
    if ( $unlocked ne "" ) {
        printear("[+] Unlocked : ");
        print $unlocked. "\n";
    }

}

sub by_count {

    my $query  = $_[0];
    my $fecets = "";

    printear_titulo("\n[+] Searching in Shodan without Results ...\n\n");

    my $code =
      toma( "https://api.shodan.io/shodan/host/count?key="
          . $api_key
          . "&query="
          . $query
          . "&facets="
          . $facets );

    $resultado = JSON->new->decode($code);
    my $total = $resultado->{"total"};
    if ( $total ne "" ) {
        printear("[+] Total : ");
        print $total. "\n";
    }
    else {
        printear( "[-] WTF !" . "\n" );
    }

}

sub by_ip {

    my $target = $_[0];

    printear("\n[+] Target : ");
    print $target. "\n";

    printear_titulo("\n[+] Getting Host Information ...\n\n");

    my $code = toma(
        "https://api.shodan.io/shodan/host/" . $target . "?key=" . $api_key );
    $resultado = JSON->new->decode($code);

    my $ip           = $resultado->{'ip'};
    my $country_name = $resultado->{'country_name'};
    my $country_code = $resultado->{'country_code'};
    my $region_name  = $resultado->{'region_name'};
    my $postal_code  = $resultado->{'postal_code'};

    if ( $ip ne "" ) {
        printear("[+] IP : ");
        print $ip. "\n";
    }
    if ( $country_name ne "" ) {
        printear("[+] Country Name : ");
        print $country_name. "\n";
    }
    if ( $country_code ne "" ) {
        printear("[+] Country Code : ");
        print $country_code. "\n";
    }
    if ( $region_name ne "" ) {
        printear("[+] Area Code : ");
        print $region_name. "\n";
    }
    if ( $postal_code ne "" ) {
        printear("[+] Postal Code : ");
        print $postal_code. "\n";
    }
    printear("[+] Hostnames : ");
    my @hostnames = @{ $resultado->{'hostnames'} };
    foreach my $host (@hostnames) {
        print $host. "\t";
    }
    print "\n";
    printear_titulo("\n[+] Getting Data ...\n\n");
    my $i           = 0;
    my @encontrados = @{ $resultado->{'data'} };
    foreach my $encontrado (@encontrados) {
        $i++;
        print "-------------------------------------\n\n";
        my $ip           = $encontrado->{"ip_str"};
        my $country      = $encontrado->{"location"}{"country_name"};
        my $product      = $encontrado->{"product"};
        my $version      = $encontrado->{"version"};
        my $data         = $encontrado->{"data"};
        my $cpe          = $encontrado->{"cpe"};
        my $time         = $encontrado->{"timestamp"};
        my $last_updated = $encontrado->{"last_update"};
        my $port         = $encontrado->{"port"};
        my $os           = $encontrado->{"os"};
        my $isp          = $encontrado->{"isp"};
        my $ans          = $encontrado->{"ans"};
        my $banner       = $encontrado->{"banner"};

        if ( $ip ne "" ) {
            printear("[+] IP : ");
            print $ip. "\n";
        }
        if ( $port ne "" ) {
            printear("[+] Port : ");
            print $port. "\n";
        }
        printear("[+] Hostnames : ");
        my @hostnames2 = @{ $encontrado->{'hostnames'} };
        foreach my $host2 (@hostnames2) {
            print $host2. "\t";
        }
        print "\n";
        if ( $country ne "" ) {
            printear("[+] Country : ");
            print $country. "\n";
        }
        if ( $product ne "" ) {
            printear("[+] Product : ");
            print $product. "\n";
        }
        if ( $version ne "" ) {
            printear("[+] Version : ");
            print $version. "\n";
        }
        if ( $data ne "" ) {
            printear("[+] Data : ");
            print "\n\n" . $data . "\n";
        }
        if ( $time ne "" ) {
            printear("[+] Time : ");
            print $time. "\n";
        }
        if ( $last_updated ne "" ) {
            printear("[+] Last Updated : ");
            print $last_updated. "\n";
        }
        if ( $cpe ne "" ) {
            printear("[+] CPE : ");
            print $cpe. "\n";
        }
        if ( $os ne "" ) {
            printear("[+] OS : ");
            print $os. "\n";
        }
        if ( $isp ne "" ) {
            printear("[+] ISP : ");
            print $isp. "\n";
        }
        if ( $asn ne "" ) {
            printear("[+] ASN : ");
            print $ans. "\n";
        }
        if ( $banner ne "" ) {
            printear("[+] Banner : ");
            print $banner. "\n";
        }
        print "\n-------------------------------------\n";

        if ( $i % 5 == 0 ) {
            printear("\n[+] Press enter to show more\n");
            <STDIN>;
        }

    }

}

sub by_search {

    my $target = $_[0];

    printear("[+] Target : ");
    print $target. "\n";

    printear_titulo("\n[+] Searching in Shodan ...\n\n");

    my $code =
      toma( "https://api.shodan.io/shodan/host/search?key="
          . $api_key
          . "&query="
          . $target
          . "&facets=" );

    $resultado = JSON->new->decode($code);

    my $total = $resultado->{'total'};

    if ( $total ne "" ) {
        printear("[+] Total : ");
        print $total. "\n";
    }
    else {
        printear("[-] WTF !");
    }

    my $ip           = $resultado->{'ip'};
    my $country_name = $resultado->{'country_name'};
    my $country_code = $resultado->{'country_code'};
    my $region_name  = $resultado->{'region_name'};
    my $postal_code  = $resultado->{'postal_code'};

    if ( $ip ne "" ) {
        printear("[+] IP : ");
        print $ip. "\n";
    }
    if ( $country_name ne "" ) {
        printear("[+] Country Name : ");
        print $country_name. "\n";
    }
    if ( $country_code ne "" ) {
        printear("[+] Country Code : ");
        print $country_code. "\n";
    }
    if ( $region_name ne "" ) {
        printear("[+] Area Code : ");
        print $region_name. "\n";
    }
    if ( $postal_code ne "" ) {
        printear("[+] Postal Code : ");
        print $postal_code. "\n";
    }

    if ( $resultado->{'hostnames'}[0] ne "" ) {
        printear("[+] Hostnames : ");
        my @hostnames = @{ $resultado->{'hostnames'} };
        foreach my $host (@hostnames) {
            print $host. "\t";
        }
        print "\n";
    }

    printear_titulo("\n[+] Getting Data ...\n\n");

    my $i = 0;

    my @encontrados = @{ $resultado->{'matches'} };
    foreach my $encontrado (@encontrados) {
        $i++;
        print "-------------------------------------\n\n";
        my $ip           = $encontrado->{"ip_str"};
        my $country      = $encontrado->{"location"}{"country_name"};
        my $product      = $encontrado->{"product"};
        my $version      = $encontrado->{"version"};
        my $data         = $encontrado->{"data"};
        my $cpe          = $encontrado->{"cpe"};
        my $time         = $encontrado->{"timestamp"};
        my $last_updated = $encontrado->{"last_update"};
        my $port         = $encontrado->{"port"};
        my $os           = $encontrado->{"os"};
        my $isp          = $encontrado->{"isp"};
        my $ans          = $encontrado->{"ans"};
        my $banner       = $encontrado->{"banner"};

        if ( $ip ne "" ) {
            printear("[+] IP : ");
            print $ip. "\n";
        }
        if ( $port ne "" ) {
            printear("[+] Port : ");
            print $port. "\n";
        }
        printear("[+] Hostnames : ");
        my @hostnames2 = @{ $encontrado->{'hostnames'} };
        foreach my $host2 (@hostnames2) {
            print $host2. "\t";
        }
        print "\n";
        if ( $country ne "" ) {
            printear("[+] Country : ");
            print $country. "\n";
        }
        if ( $product ne "" ) {
            printear("[+] Product : ");
            print $product. "\n";
        }
        if ( $version ne "" ) {
            printear("[+] Version : ");
            print $version. "\n";
        }
        if ( $data ne "" ) {
            printear("[+] Data : ");
            print "\n\n" . $data . "\n";
        }
        if ( $time ne "" ) {
            printear("[+] Time : ");
            print $time. "\n";
        }
        if ( $last_updated ne "" ) {
            printear("[+] Last Updated : ");
            print $last_updated. "\n";
        }
        if ( $cpe ne "" ) {
            printear("[+] CPE : ");
            print $cpe. "\n";
        }
        if ( $os ne "" ) {
            printear("[+] OS : ");
            print $os. "\n";
        }
        if ( $isp ne "" ) {
            printear("[+] ISP : ");
            print $isp. "\n";
        }
        if ( $asn ne "" ) {
            printear("[+] ASN : ");
            print $ans. "\n";
        }
        if ( $banner ne "" ) {
            printear("[+] Banner : ");
            print $banner. "\n";
        }
        print "\n-------------------------------------\n";

        if ( $i % 5 == 0 ) {
            printear("\n[+] Press enter to show more\n");
            <STDIN>;
        }

    }

}

sub printear {
    cprint( "\x036" . $_[0] . "\x030" );
}

sub printear_logo {
    cprint( "\x037" . $_[0] . "\x030" );
}

sub printear_titulo {
    cprint( "\x0310" . $_[0] . "\x030" );
}

sub toma {
    return $nave->get( $_[0] )->content;
}

sub sintax {
    printear("\n[+] Sintax : ");
    print "perl $0 <option> <value>\n";
    printear("\n[+] Options : \n\n");
    print "-ip <ip> : Host Information\n";
    print "-count <query> : Search Shodan without Results\n";
    print "-search <query> : Search Shodan\n";
    print "-query : List the saved search queries\n";
    print
      "-query_search <query> : Search the directory of saved search queries\n";
    print "-query_tags : List the most popular tags\n";
    print "-services : List all services that Shodan crawls\n";
    print "-resolve <host> : DNS Lookup\n";
    print "-reverse <ip> : Reverse DNS Lookup\n";
    print "-myip : My IP Address\n";
    print "-api_info : API Plan Information\n";
    printear("\n[+] Example : ");
    print "perl shodan.pl -search petardas\n";
    copyright();
}

sub head {
    printear_logo("\n-- == Shodan Tool 0.6 == --\n\n");
}

sub copyright {
    printear_logo("\n\n-- == (C) Doddy Hackman 2015 == --\n\n");
    exit(1);
}

# The End ?
