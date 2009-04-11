=head1 NAME

Net::SNMP::XS - speed up Net::SNMP by decoding in XS, with limitations

=head1 SYNOPSIS

 use Net::SNMP::XS;

 # loading it is enough, there are no public symbols

=head1 DESCRIPTION

This module tries to speed up Net::SNMP response packet decoding.

It does this by overriding a few selected internal method by (almost)
equivalent XS methods.

This currently reduces decode time by a factor of ten for typical bulk
responses.

There are currently the following limitations when using this module:

=over 4

=item overriding internal functions might cause the module to
malfunction with future versions of Net::SNMP

=item only leading dots for oids are supported

=item error messages will be simpler/different

=item oid components are limited to unsigned 32 bit integers

=item translation will be ignored (all values will be delivered "raw")

=item a moderately modern (>= C99) C compiler is required

=item only tested with 5.10, no intentions to port to older perls

=item duplicate OIDs are not supported

=item REPORT PDUs are not supported

=back

=cut

package Net::SNMP::XS;

use strict qw(vars subs);
no warnings;

use Guard;

use Net::SNMP::PDU ();
use Net::SNMP::Message ();
use Net::SNMP::MessageProcessing ();

our $VERSION;
our $old_prepare;

BEGIN {
   $VERSION = '0.02';

   $old_prepare = \&Net::SNMP::MessageProcessing::prepare_data_elements;

   # this overrides many methods inside
   require XSLoader;
   XSLoader::load Net::SNMP::XS, $VERSION;
}

sub Net::SNMP::MessageProcessing::prepare_data_elements {
   my ($self, $msg) = @_;

   set_msg $msg, $msg->{_buffer};
   scope_guard \&clr_msg;
   &$old_prepare
}

{
   package Net::SNMP::Message;

   Net::SNMP::XS::set_type INTEGER          , \&_process_integer32;
   Net::SNMP::XS::set_type OCTET_STRING     , \&_process_octet_string;
   Net::SNMP::XS::set_type NULL             , \&_process_null;
   Net::SNMP::XS::set_type OBJECT_IDENTIFIER, \&_process_object_identifier;
   Net::SNMP::XS::set_type SEQUENCE         , \&_process_sequence;
   Net::SNMP::XS::set_type IPADDRESS        , \&_process_ipaddress;
   Net::SNMP::XS::set_type COUNTER          , \&_process_counter;
   Net::SNMP::XS::set_type GAUGE            , \&_process_gauge;
   Net::SNMP::XS::set_type TIMETICKS        , \&_process_timeticks;
   Net::SNMP::XS::set_type OPAQUE           , \&_process_opaque;
   Net::SNMP::XS::set_type COUNTER64        , \&_process_counter64;
   Net::SNMP::XS::set_type NOSUCHOBJECT     , \&_process_nosuchobject;
   Net::SNMP::XS::set_type NOSUCHINSTANCE   , \&_process_nosuchinstance;
   Net::SNMP::XS::set_type ENDOFMIBVIEW     , \&_process_endofmibview;
   Net::SNMP::XS::set_type GET_REQUEST      , \&_process_get_request;
   Net::SNMP::XS::set_type GET_NEXT_REQUEST , \&_process_get_next_request;
   Net::SNMP::XS::set_type GET_RESPONSE     , \&_process_get_response;
   Net::SNMP::XS::set_type SET_REQUEST      , \&_process_set_request;
   Net::SNMP::XS::set_type TRAP             , \&_process_trap;
   Net::SNMP::XS::set_type GET_BULK_REQUEST , \&_process_get_bulk_request;
   Net::SNMP::XS::set_type INFORM_REQUEST   , \&_process_inform_request;
   Net::SNMP::XS::set_type SNMPV2_TRAP      , \&_process_v2_trap;
   Net::SNMP::XS::set_type REPORT           , \&_process_report;
}

1;

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

