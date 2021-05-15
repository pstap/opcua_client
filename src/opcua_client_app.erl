%%%-------------------------------------------------------------------
%% @doc opcua_client public API
%% @end
%%%-------------------------------------------------------------------

-module(opcua_client_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    opcua_client_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
