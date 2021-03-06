package CIF::REST::Feeds;
use Mojo::Base 'Mojolicious::Controller';

use CIF qw/$Logger/;

sub index {
    my $self = shift;
	
	my $res = $self->cli->search({
		token     => $self->token,
		filters   => {
			otype        => scalar $self->param('otype')        || undef,
			confidence   => scalar $self->param('confidence')   || undef,
			cc           => scalar $self->param('cc')           || undef,
			tags         => scalar $self->param('tag')          || undef,
			provider     => scalar $self->param('provider')     || undef,
			tlp          => scalar $self->param('tlp')          || undef,
		},
		feed      => 1,
	});
	
	$self->stash(observables => $res);
    $self->respond_to(
        json    => { json => $res },
        html    => { template => 'feeds/index' },
    );
}

sub show {
  my $self  = shift;
  
  my $res = $self->cli->search({
      token => $self->token,
      id    => scalar $self->param('feed'),
      feed  => 1,
  });
  
  $self->stash(feeds => $res);
    $self->respond_to(
        json    => { json => $res },
    );
}

sub create {
    my $self = shift;
    
    my $nowait = scalar $self->param('nowait') || 0;
    
    my $res = $self->cli->ping_write({
        token   => $self->token,
    });
    
    if($res == 0){
        $self->render(json   => { 'message' => 'unauthorized' }, status => 401 );
        return;
    }
    
    if($nowait){
        $Logger->debug('forking...');
        $SIG{CHLD} = 'IGNORE';
        my $child = fork();
        
        unless(defined($child)){
            die "fork(): $!";
        }
        
        if($child == 0){
            my $data = $self->req->json();
            $data = [$data] unless(ref($data) eq 'ARRAY');
            
            $Logger->debug('starting submission...');
            
            my $res = $self->cli->submit_feed({
            	token  => $self->token,
                feed   => $data,
            });
            
            $Logger->debug('submission complete...');
            exit(0);
        } else {
            $self->respond_to(
                json    => { json => { 'message' => 'submission accepted, processing may take time' }, status => 201 },
            );
            return;
        }
    } else {
        my $data = $self->req->json();
        $data = [$data] unless(ref($data) eq 'ARRAY');
        
        my $res = $self->cli->submit_feed({
        	token  => $self->token,
            feed   => $data,
        });
        
        if($#{$res} >= 0){
            $self->res->headers->add('X-Location' => $self->req->url->to_string());
            $self->res->headers->add('X-Id' => @{$res}[0]);
        
            $self->respond_to(
                json    => { json => $res, status => 201 },
            );
        } else {
            $self->respond_to(
                json    => { json => { 'message' => 'failed to create feed' }, status => 403 }
            );
        }
    }
}
    
1;