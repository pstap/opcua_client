%%% @author Peter
%%% @copyright (C) 2021, Peter
%%% @doc
%%% Support for the Secure Channel Service Set. Described in OPC-UA Spec Part 4
%%% @end
%%% Created : 26 May 2021 by Peter

-module(ua_secure_channel).


-compile([export_all, debug_info]).

make_open_secure_channel_request() ->
    RequestHeader = #{<<"type">> => <<"RequestHeader">>,
		      <<"fields">> => #{<<"AuthenticationToken">> => null,
					<<"Timestamp">> => null,
					<<"RequestHandle">> => 10,
					<<"ReturnDiagnostics">> => 0,
					<<"AuditEntryId">> => "",
					<<"TimeoutHint">> => 30000,
					<<"AdditionalHeader">> => null}},
    #{<<"type">> => <<"OpenSecureChannelRequest">>,
      <<"fields">> =>
	  #{<<"RequestHeader">> => RequestHeader,
	    <<"ClientProtocolVersion">> => 0,
	    <<"RequestType">> => 0,
	    <<"SecurityMode">> => 1,
	    <<"ClientNonce">> => <<>>,
	    <<"RequestedLifetime">> => 50000}}.
