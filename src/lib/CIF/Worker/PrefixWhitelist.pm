package CIF::Worker::PrefixWhitelist;

use strict;
use warnings;
use Data::Dumper;

use Mouse;
use CIF qw/is_ip $Logger/;

with 'CIF::WorkerRole';

sub understands {
    my $self = shift;
    my $args = shift;

    return unless($args->{'prefix'});
    return unless(is_ip($args->{'prefix'}));
    return unless($args->{'confidence'} > 25);
    return 1;
}

sub process {
    my $self = shift;
    my $data = shift;
    
    my $obs = $data->{'observable'};
    
    return unless(tagged_whitelist($data->{'tags'}));
    
    $obs = {
        observable  => $data->{'prefix'},
        prefix      => $data->{'prefix'},
        asn         => $data->{'asn'},
        asn_desc    => $data->{'asn_desc'},
        cc          => $data->{'cc'},
        related     => $data->{'id'},
        tags        => 'whitelist',
        tlp         => $data->{'tlp'} || CIF::TLP_DEFAULT,
        group       => $data->{'group'} || CIF::GROUP_DEFAULT,
        provider    => $data->{'provider'} || CIF::PROVIDER_DEFAULT,
        confidence  => $self->degrade_confidence($data->{'confidence'} || 25),
        application => $data->{'application'},
        portlist    => $data->{'portlist'},
        protocol    => $data->{'protocol'},
        altid       => $data->{'altid'},
        altid_tlp   => $data->{'altid_tlp'} || $data->{'tlp'} || CIF::TLP_DEFAULT,
        longitude   => $data->{'longitude'},
        latitude    => $data->{'latitude'},
        timezone    => $data->{'timezone'},
        peers       => $data->{'peers'},
        otype       => 'ipv4',
    };
    $Logger->debug(Dumper($obs));
    return [$obs];
}

sub tagged_whitelist {
    my $tags = shift || return 0;
    
    $tags = [ $tags ] unless(ref($tags) && ref($tags) eq 'ARRAY');
    
    foreach my $t (@$tags){
        return 1 if($t eq 'whitelist');       
    }
}

__PACKAGE__->meta->make_immutable();

1;