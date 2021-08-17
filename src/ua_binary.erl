%%% @author Peter <peter@beep>
%%% @copyright (C) 2021, Peter
%%% @doc
%%%
%%% @end
%%% Created : 11 May 2021 by Peter <peter@beep>

-module(ua_binary).

-compile([export_all, debug_info]).

%% API
-export([encode_obj/1]).
-export([encode_obj/2]).



%% <opc:StructuredType Name="OpenSecureChannelRequest" BaseType="ua:ExtensionObject">
%%   <opc:Field Name="RequestHeader" TypeName="tns:RequestHeader" />
%%   <opc:Field Name="ClientProtocolVersion" TypeName="opc:UInt32" />
%%   <opc:Field Name="RequestType" TypeName="tns:SecurityTokenRequestType" />
%%   <opc:Field Name="SecurityMode" TypeName="tns:MessageSecurityMode" />
%%   <opc:Field Name="ClientNonce" TypeName="opc:ByteString" />
%%   <opc:Field Name="RequestedLifetime" TypeName="opc:UInt32" />
%% </opc:StructuredType>

-define(UINT, unsigned-little).
-define(INT, signed-little).
-define(FLOAT, float-little).

-spec encode_field(Type :: binary() | list(), F :: term()) -> binary().
encode_field(Name, F) when is_list(Name) ->
    encode_field(list_to_binary(Name), F);
encode_field(<<"Boolean">>, true) -> <<1>>;
encode_field(<<"Boolean">>, false) -> <<0>>;
encode_field(<<"SByte">>, F) -> <<F:1/?INT>>;
encode_field(<<"Byte">>, F) -> <<F:1/?UINT>>;
encode_field(<<"UInt16">>, F) -> <<F:16/?UINT>>;
encode_field(<<"Int16">>, F) -> <<F:16/?INT>>;
encode_field(<<"UInt32">>, F) -> <<F:32/?UINT>>;
encode_field(<<"Int32">>, F) -> <<F:32/?INT>>;
encode_field(<<"UInt64">>, F) -> <<F:64/?UINT>>;
encode_field(<<"Int64">>, F) -> <<F:64/?INT>>;
encode_field(<<"Float">>, F) -> <<F:32/?FLOAT>>;
encode_field(<<"Double">>, F) -> <<F:64/?FLOAT>>;
encode_field(<<"String">>, F) when is_list(F) ->
    L = length(F),
    B = list_to_binary(F),
    <<L:32/?INT,B/binary>>;
encode_field(<<"String">>, F) when is_binary(F) ->
    encode_field(<<"ByteString">>, F);
encode_field(<<"DateTime">>, _F) ->
    %% TODO 
    <<0:64/unsigned-little>>;
encode_field(<<"GUID">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"ByteString">>, F) ->
    L = byte_size(F),
    <<L:32/?INT,F/binary>>;
encode_field(<<"XmlElement">>, F) ->
    encode_field(<<"ByteString">>, F);
encode_field(<<"NodeId">>, null) -> <<0,0>>; % encoded as a 2-byte NodeId
encode_field(<<"NodeId">>, #{<<"IdentifierType">> := <<"TwoByte">>, 
			     <<"Value">> := V}) ->
    <<16#00:8/?UINT,V:8/?UINT>>;
encode_field(<<"NodeId">>, #{<<"Namespace">> := NameSpaceID, 
			     <<"IdentifierType">> := <<"FourByte">>, 
			     <<"Value">> := V}) when NameSpaceID < 256, V < 16#10000 ->
    <<16#01:8/?UINT,NameSpaceID:8/?UINT,V:16/?UINT>>;
encode_field(<<"ExpandedNodeId">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"StatusCode">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"QualifiedName">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"LocalizedText">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"ExtensionObject">>, null) -> <<0,0,0>>; % 2 byte NodeId and no body
encode_field(<<"ExtensionObject">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"DataValue">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"Variant">>, _F) ->
    %% TODO
    <<0>>;
encode_field(<<"DiagnosticInfo">>, _F) ->
    %% TODO
    <<0>>.

-spec encode_obj(Obj :: map()) -> binary().
encode_obj(Obj = #{<<"type">> := Type}) ->
    encode_obj(Obj, Type).

-spec encode_obj(Obj :: map(), Type :: binary()) -> binary().
encode_obj(Obj, Type) ->
    case ua_nodeset:get_def(Type) of
	{ok, {ua_prim, _}} -> encode_field(Type, Obj);
	{ok, {Class, Def}} -> encode_obj(Obj, Class, Def, <<>>);
	{error, not_found} -> 
	    io:format("Unknown type ~p~n", [Type]), exit(unknown_type)
    end.

-spec encode_obj(Obj :: map(), ua_enum, Def :: list({binary(), integer()}), _Acc) -> binary().
encode_obj(Obj, ua_enum, Def, _Acc) when is_binary(Obj) ->
    %% lookup the value
    case lists:keysearch(Obj, 1, Def) of
	false -> exit("unknown enumeration value");
	{value, {Obj, NumericID}} -> <<NumericID:32/?INT>>
    end;
encode_obj(Obj, ua_enum, _Def, _Acc) when is_number(Obj) ->
    <<Obj:32/?INT>>;
encode_obj(_Obj, _Class, [], Acc) -> Acc;
encode_obj(Obj = #{<<"fields">> := ObjFields}, 
	   ua_struct,
	   [{FieldName, FieldType}|RestFields], Acc) ->
    Field = maps:get(FieldName, ObjFields),
    B = encode_obj(Field, FieldType), 
    NewAcc = <<B/binary,Acc/binary>>,
    encode_obj(Obj, ua_struct, RestFields, NewAcc).

