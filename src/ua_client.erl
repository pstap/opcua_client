%%%-------------------------------------------------------------------
%%% @author Peter <peter@beep>
%%% @copyright (C) 2021, Peter
%%% @doc
%%%
%%% @end
%%% Created :  8 May 2021 by Peter <peter@beep>
%%%-------------------------------------------------------------------
-module(ua_client).

-behaviour(gen_statem).

%% API
-export([start_link/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).
-export([disconnected/3]).
-export([connected/3]).
-export([establish_secure_channel/3]).
-export([establish_session/3]).

-record(data, {
               host :: string(), 
               port :: integer(),
               connopts :: map(),
               sockproc :: pid()
              }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_statem process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link(Host :: string(), 
                 Port :: integer()) ->
          {ok, Pid :: pid()} |
          ignore |
          {error, Error :: term()}.
start_link(Host, Port) ->
    gen_statem:start_link(?MODULE, [Host, Port], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Define the callback_mode() for this callback module.
%% @end
%%--------------------------------------------------------------------
-spec callback_mode() -> gen_statem:callback_mode_result().
callback_mode() -> state_functions.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_statem is started using gen_statem:start/[3,4] or
%% gen_statem:start_link/[3,4], this function is called by the new
%% process to initialize.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) ->
          gen_statem:init_result(atom()).
init([Host, Port]) ->
    process_flag(trap_exit, true),
    Actions = [{next_event, internal, connect}],
    Data = #data{host=Host,port=Port},
    {ok, disconnected, Data, Actions}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one function like this for each state name.
%% Whenever a gen_statem receives an event, the function 
%% with the name of the current state (StateName) 
%% is called to handle the event.
%% @end
%% -spec state_name('enter',
%%               OldState :: atom(),
%%               Data :: term()) ->
%%        gen_statem:state_enter_result('state_name');
%%              (gen_statem:event_type(),
%%               Msg :: term(),
%%               Data :: term()) ->
%%        gen_statem:event_handler_result(atom()).
%% state_name({call,Caller}, _Msg, Data) ->
%%     {next_state, state_name, Data, [{reply,Caller,ok}]}.
%%--------------------------------------------------------------------


%% Handle the internal event
disconnected(internal, connect, Data) ->
    %% Try to connect
    io:format("Connecting to server~n"),
    {ok, SockProc} = ua_client_sock:start_link(self(), Data#data.host, Data#data.port),
    HelloBin = ua_conn_proto:encode_hello(<<"localhost">>),
    ok = ua_client_sock:send(SockProc, HelloBin),
    receive
        {SockProc, Bin} ->
            io:format("Received binary from socket"),
            <<"ACKF",_Size:32/unsigned-little,Ack/binary>> = Bin,
            {ok, ConnOpts} = ua_conn_proto:parse_ack(Ack),
            io:format("Got connopts ~p~n", [ConnOpts]),
            NewData = Data#data{
                        sockproc=SockProc,
                        connopts=ConnOpts
                       },
	    Actions = [{next_event, internal, establish}],
            {next_state, establish_secure_channel, NewData, Actions}
    end.


establish_secure_channel(internal, establish, Data) ->
    io:format("establishing secure channel~n"),
    MsgBin = encode_open_secure_channel_msg(),
    
    SockProc = Data#data.sockproc,
    ok = ua_client_sock:send(SockProc, MsgBin),
    receive
	{SockProc, Bin} -> io:format("Got back ~B bytes from socket", [byte_size(Bin)])		
    end,
    io:format("Secure channel established ~n"),
    NewData = Data,
    Actions = [{next_event, internal, establish}],
    {next_state, establish_session, NewData, Actions}.

establish_session(internal, establish, Data) ->
    io:format("Establishing session~n"),
    io:format("Session establishment not implemented!!"),
    {next_state, connected, Data}.

%% Our client socket died
connected(info, {'EXIT', SockProc, _Reason}, 
          Data = #data{sockproc=SockProc}) ->
    disconnect(Data).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_statem when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_statem terminates with
%% Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: term(), State :: term(), Data :: term()) ->
          any().
terminate(_Reason, _State, _Data) ->
    void.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(
        OldVsn :: term() | {down,term()},
        State :: term(), Data :: term(), Extra :: term()) ->
          {ok, NewState :: term(), NewData :: term()} |
          (Reason :: term()).
code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
disconnect(Data) ->
    io:format("Disconnecting for some reason~n"),
    NewData = Data#data{sockproc=none, connopts=none},
    Actions = [{next_event, internal, connect}],
    {next_state, disconnected, NewData, Actions}.


%%% SECURE CHANNEL IMPLEMENTATION
%%% TODO MOVE ME OUT FROM HERE TO ANOTHER MODULE
-define(SECURITY_POLICY_URI_NONE, <<"http://opcfoundation.org/UA/SecurityPolicy#None">>).
-define(SECURITY_POLICY_URI_NONE_LEN, 47).

-define(MSG_HEADER_SIZE_BYTES, 12).

encode_open_secure_channel_msg() ->
    SecurityHeader = encode_asymmetric_security_header(),
    SequenceHeader = <<0:32/unsigned-little, 16#DEAD:32/unsigned-little>>,
    Req = encode_open_secure_channel_request(),
    NodeId = <<1,0,446:16/unsigned-little>>,
    L = byte_size(SecurityHeader) + 
	byte_size(SequenceHeader) + 
	byte_size(Req) + 
	byte_size(NodeId) +
	?MSG_HEADER_SIZE_BYTES,
    MsgHeader = <<"OPNF",L:32/unsigned-little,0:32/unsigned-little>>,
    <<MsgHeader/binary,
      SecurityHeader/binary,
      SequenceHeader/binary,
      NodeId/binary,
      Req/binary>>.

encode_open_secure_channel_request() ->
    RequestHeader = encode_request_header(),
    ClientProtocolVersion = 16#aaaa, %% UINT32
    RequestType = 0, %% 32 bit enumed value. 0 = issue, 1 = renew
    SecurityMode = 1, %% 32 bit enumed vaule. Invalid = 0, None = 1, Sign = 2, sign and encrypt = 3
    ClientNonce = <<0,0,0,0>>, %% empty bytestring (empt array of byte? variant?)
    RequestLifetime = 30000, %% UInt32 (ms)
    <<
      RequestHeader/binary,
      ClientProtocolVersion:32/little-unsigned,
      RequestType:32/little-unsigned,
      SecurityMode:32/little-unsigned,
      ClientNonce/binary,
      RequestLifetime:32/little-unsigned
    >>.

encode_request_header() ->
    AuthenticationToken = encode_null_nodeid(),
    Timestamp = get_current_timestamp_binary(),
    RequestHandle = 0, %% u32,
    ReturnDiagnostics = 0, %% u32
    AuditEntryId = encode_string(""),
    TimeoutHint = 0, %% u32
    AdditionalHeader = encode_null_extension_object(),
    <<
      AuthenticationToken/binary,
      Timestamp/binary,
      RequestHandle:32/unsigned-little,
      ReturnDiagnostics:32/unsigned-little,
      AuditEntryId/binary,
      TimeoutHint:32/unsigned-little,
      AdditionalHeader/binary      
    >>.
    
encode_null_nodeid() ->
    %% NULL 2 byte node id
    <<0,0>>.

encode_null_extension_object() ->
    <<0,0,0>>.

-define(UA_EPOCH_DELTA, 11644473600).
-define(NUM_NANO_SEC_INTERVALS, 10.0e7).

get_current_timestamp_binary() ->
    %% A DateTime value shall be encoded as a 64-bit signed integer (see Clause 5.2.2.2) which
    %% represents the number of 100 nanosecond intervals since January 1, 16 01 (UTC).
    %% UA Epoch = 50522745600
    %% Unix Epoch =  62167219200
    %% Delta = 11644473600

    %% TODO FIXME - I don't work
    CurrentSec = os:system_time(second),
    _TimeSec = (CurrentSec + ?UA_EPOCH_DELTA) * ?NUM_NANO_SEC_INTERVALS,
    <<0:64/signed-little>>.

encode_string(S) when is_list(S) ->
    L = length(S),
    B = list_to_binary(S),
    <<L:32/unsigned-little,B/binary>>.

encode_asymmetric_security_header() ->
    <<?SECURITY_POLICY_URI_NONE_LEN:32/unsigned-little,
      ?SECURITY_POLICY_URI_NONE/binary,
      0:32/signed-little,
      0:32/signed-little>>.
