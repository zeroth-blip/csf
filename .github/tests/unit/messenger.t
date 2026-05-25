#!/usr/bin/env perl

use strict;
use warnings;

use FindBin qw($Bin);
use Test::More;
use lib "$Bin/../lib";

use TestBootstrap ();

{
    package Local::FakeMessengerClient;

    sub new {
        my ($class, $payload) = @_;
        return bless { buf => [ split //, $payload ] }, $class;
    }

    sub read {
        my $self = shift;
        # Caller passes: $client->read($char, 1)
        # $_[0] aliases the caller's $char, $_[1] aliases the length argument.
        if (@{ $self->{buf} }) {
            $_[0] = shift @{ $self->{buf} };
        } else {
            $_[0] = "\n";
        }
        return 1;
    }
}

sub load_messenger {
    my (%config) = @_;
    $config{IPV6}         //= 0;
    $config{MESSENGER6}   //= 0;
    $config{RECAPTCHA_NAT} //= '';
    $config{DEBUG}        //= 0;
    TestBootstrap::reload_module_with_config('ConfigServer::Messenger', \%config);
    return;
}

subtest 'init returns a blessed instance for version 2 without touching ssl directories' => sub {
    load_messenger();

    my $obj = ConfigServer::Messenger->init(2);

    isa_ok($obj, 'ConfigServer::Messenger', 'init returns a Messenger object for the v2 (TEXT) flavor');
    can_ok($obj, 'start');
};

subtest '_read_request_line returns an LF-terminated request line without the trailing newline' => sub {
    load_messenger();

    my $client = Local::FakeMessengerClient->new("GET / HTTP/1.0\n");
    my $line = ConfigServer::Messenger::_read_request_line($client);

    is($line, 'GET / HTTP/1.0', 'trailing LF is chomped off the returned line');
};

subtest '_read_request_line strips a trailing CR when the request uses CRLF' => sub {
    load_messenger();

    my $client = Local::FakeMessengerClient->new("GET /resource HTTP/1.1\r\n");
    my $line = ConfigServer::Messenger::_read_request_line($client);

    is($line, 'GET /resource HTTP/1.1', 'CRLF terminator is reduced to a bare request line');
};

subtest '_read_request_line stops reading once MAX_LINE_LENGTH bytes have been consumed' => sub {
    load_messenger();

    my $payload = ('A' x 5000) . "\n";
    my $client = Local::FakeMessengerClient->new($payload);
    my $line = ConfigServer::Messenger::_read_request_line($client);

    ok(length($line) > ConfigServer::Messenger::MAX_LINE_LENGTH(),
        'overlong request lines exit the read loop without consuming the entire payload');
    ok(length($line) <= ConfigServer::Messenger::MAX_LINE_LENGTH() + 1,
        'read stops within one byte of the documented MAX_LINE_LENGTH cap');
    unlike($line, qr/\n/, 'returned line never contains an embedded newline');
};

done_testing;
