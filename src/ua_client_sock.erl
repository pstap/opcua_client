%%%-------------------------------------------------------------------
%%% @author Peter <peter@beep>
%%% @copyright (C) 2021, Peter
%%% @doc
%%%
%%% @end
%%% Created : 27 Apr 2021 by Peter <peter@beep>
%%%-------------------------------------------------------------------
-module(ua_client_sock).

-behaviour(gen_server).

%% API
-export([start_link/3]).

-export([send/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-record(state, {
                client :: pid(),
                socket :: port(),
                left :: integer() | atom(),
                acc :: binary() | atom()
               }).


-define(SOCKET_OPTS, [binary, {active, once}, {packet, raw}]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Send a binary over the socket
%% @end
%%--------------------------------------------------------------------
-spec send(Pid :: pid(), Binary :: binary()) -> ok.
send(Pid, Binary) ->
    logger:info("Sending data on socket~n"),
    gen_server:call(Pid, {send, Binary}).


%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Client :: pid(), Address :: string(), Port :: integer()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Client, Address, Port) ->
    gen_server:start_link(?MODULE, {Client, Address, Port}, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) -> {ok, State :: term()} |
          {ok, State :: term(), Timeout :: timeout()} |
          {ok, State :: term(), hibernate} |
          {stop, Reason :: term()} |
          ignore.
init({Client, Address, Port}) ->
    process_flag(trap_exit, true),
    %% Connect to the server
    case gen_tcp:connect(Address, Port, ?SOCKET_OPTS) of
        {ok, Sock} ->
            {ok, #state{client=Client, socket=Sock, left=none, acc=none}};
        {error, Error} ->
            {stop, Error}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
          {reply, Reply :: term(), NewState :: term()} |
          {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
          {reply, Reply :: term(), NewState :: term(), hibernate} |
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
          {stop, Reason :: term(), NewState :: term()}.
handle_call({send, Binary}, _From, State) ->
    Sock = State#state.socket,
    ok = gen_tcp:send(Sock, Binary),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_cast(Request :: term(), State :: term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: term(), NewState :: term()}.
handle_cast(_Request, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: normal | term(), NewState :: term()}.
handle_info({tcp, Socket, Data}, State) ->
    NewState = rx(Data, State),
    inet:setopts(Socket, [{active,once}]),
    {noreply, NewState};
handle_info({tcp_closed, Socket}, #state{socket=Socket}) ->
    exit(server_socket_closed);
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
          {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
    Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handle received data.
%% @end
%%--------------------------------------------------------------------
-spec rx(Bin :: binary(), State :: term()) -> term().
rx(Bin = <<_Type:3/binary,_Final:1/binary,Length:32/little-unsigned, _/binary>>,    
   State = #state{left = none, acc = none}) ->
    %% State: Have not received header, nothing in acc
    Received = byte_size(Bin),
    if
        %% Received the whole message and nothing else
        Received == Length -> 
            ok = send_message(State#state.client, Bin),
            State;
        %% Received extra
        Received > Length ->
            %% Handle whole message, recurse on the rest
            <<Message:Length/binary, Rest/binary>> = Bin,
            ok = send_message(State#state.client, Message),
            rx(State, Rest);
        Received < Length ->
            Left = Length - Received, %% how much left do we have to receive?
            %% return the state
            State#state{left = Left, acc = Bin}
    end;
rx(Bin, State = #state{left = none, acc = none}) ->
    %% State: nothing received yet, don't receive a whole header
    State#state{acc=Bin};
rx(Bin, State = #state{left = none, acc = Acc}) ->
    %% State: already received data, 
    NewBin = <<Acc/binary,Bin/binary>>,
    State#state{acc = NewBin};
rx(Bin, State = #state{left = Left, acc = Acc}) when Left == byte_size(Bin) ->
    Message = <<Acc/binary,Bin/binary>>,
    ok = send_message(State#state.client, Message),
    State#state{left=none, acc=none};
rx(Bin, State = #state{left=Left, acc=Acc}) ->
    Received = byte_size(Bin),
    case Left - Received of
        NewLeft when NewLeft > 0 ->
            NewAcc = <<Acc/binary, Bin/binary>>,
            State#state{left=NewLeft, acc=NewAcc};
        NewLeft when NewLeft < 0 ->
            <<Tail:Left/binary,Rest/binary>> = Bin,
            Message = <<Acc/binary,Tail/binary>>,
            ok = send_message(State#state.client, Message),
            rx(Rest, State#state{left=none, acc=none})
    end.



%%--------------------------------------------------------------------
%% @private
%% @doc
%% send a full chunk back to the client
%% @end
%%--------------------------------------------------------------------
send_message(Pid, Bin) ->
    Pid ! {self(), Bin},
    ok.
