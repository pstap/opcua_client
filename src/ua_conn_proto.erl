%%%-------------------------------------------------------------------
%%% @author Peter <peter@beep>
%%% @copyright (C) 2021, Peter
%%% @doc
%%%
%%% @end
%%% Created : 27 Apr 2021 by Peter <peter@beep>
%%%-------------------------------------------------------------------
-module(ua_conn_proto).

%% Constants
-define(PROTOCOL_VERSION, 1).
-define(RECEIVE_BUFFER_SIZE, 4096).
-define(SEND_BUFFER_SIZE, 4096).
-define(MAX_MESSAGE_SIZE, 4096).
-define(MAX_CHUNK_COUNT, 4096).

-define(MSG_HEADER_SIZE, 8).

%% Records
-record(msg_header, {type, is_final, size}).

-export([encode_hello/1,
         encode_hello/6,
         parse_ack/1,
         parse_msg_header/1,
         msg_header_msg_size/1,
         msg_header_size/0
        ]).

%% NOTE: Only implemented basic client side API. Not common with server

%% API
msg_header_msg_size(H = #msg_header{size=Size}) when is_record(H, msg_header)->
    Size.

msg_header_size() ->
    ?MSG_HEADER_SIZE.

encode_hello(EndPointURL) ->
    encode_hello(?PROTOCOL_VERSION,
                 ?RECEIVE_BUFFER_SIZE,
                 ?SEND_BUFFER_SIZE,
                 ?MAX_MESSAGE_SIZE,
                 ?MAX_CHUNK_COUNT, EndPointURL).

encode_hello(ProtocolVersion,
             ReceiveBufferSize,
             SendBufferSize,
             MaxMessageSize,
             MaxChunkCount,
             EndpointURL) ->
    MsgBody = hello_msg(ProtocolVersion,
                        ReceiveBufferSize,
                        SendBufferSize,
                        MaxMessageSize,
                        MaxChunkCount,
                        EndpointURL),
    Header = make_header(hello, true, byte_size(MsgBody)),
    <<Header/binary,MsgBody/binary>>.

-spec parse_ack(Bytes :: binary()) -> {ok, map()}.
parse_ack(Bytes) when is_binary(Bytes) ->
    <<ProtocolVersion:32/unsigned-little,
      ReceiveBufferSize:32/unsigned-little,
      SendBufferSize:32/unsigned-little,
      MaxMessageSize:32/unsigned-little,
      MaxChunkCount:32/unsigned-little>> = Bytes,
    {ok, #{<<"ProtocolVersion">> => ProtocolVersion,
           <<"ReceiveBufferSize">> => ReceiveBufferSize,
           <<"SendBufferSize">> => SendBufferSize,
           <<"MaxMessageSize">> => MaxMessageSize,
           <<"MaxChunkCount">> => MaxChunkCount}}.


parse_msg_header(HeaderBin) when is_binary(HeaderBin) ->
    <<Type:3/binary,IsFinal:1/binary,Size:32/unsigned-little>> = HeaderBin,
    case {Type, IsFinal} of
        {<<"HEL">>, <<"F">>} ->
            {ok, #msg_header{type=hello,is_final=true,size=Size}};
        {<<"ACK">>, <<"F">>} ->
            {ok, #msg_header{type=ack,is_final=true,size=Size}};
        _ -> {error, unknown_header_type}
    end.

%% Private
hello_msg(ProtocolVersion,
          ReceiveBufferSize,
          SendBufferSize,
          MaxMessageSize,
          MaxChunkCount,
          EndpointURL) ->
    EndPointSize = byte_size(EndpointURL),
    <<ProtocolVersion:32/unsigned-little,
      ReceiveBufferSize:32/unsigned-little,
      SendBufferSize:32/unsigned-little,
      MaxMessageSize:32/unsigned-little,
      MaxChunkCount:32/unsigned-little,
      EndPointSize:32/unsigned-little,
      EndpointURL/binary>>.

make_header(hello, true, MsgBodySize) when is_integer(MsgBodySize) ->
    TotalSize = ?MSG_HEADER_SIZE + MsgBodySize,
    <<"HEL","F",TotalSize:32/unsigned-little>>.
