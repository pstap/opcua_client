%%% @author Peter <peter@beep>
%%% @copyright (C) 2021, Peter
%%% @doc
%%%
%%% @end
%%% Created : 11 May 2021 by Peter <peter@beep>

-module(ua_binary).

-compile([export_all, debug_info]).



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


is_primitive(<<"Boolean">>) -> true;
is_primitive(<<"SByte">>) -> true;
is_primitive(<<"Byte">>) -> true;
is_primitive(<<"UInt16">>) -> true;
is_primitive(<<"Int16">>) -> true;
is_primitive(<<"UInt32">>) -> true;
is_primitive(<<"Int32">>) -> true;
is_primitive(<<"UInt64">>) -> true;
is_primitive(<<"Int64">>) -> true;
is_primitive(<<"Float">>) -> true;
is_primitive(<<"Double">>) -> true;
is_primitive(<<"String">>) -> true;
is_primitive(<<"DateTime">>) -> true;
is_primitive(<<"GUID">>) -> true;
is_primitive(<<"ByteString">>) -> true;
is_primitive(<<"XmlElement">>) -> true;
is_primitive(<<"NodeId">>) -> true;
is_primitive(<<"ExpandedNodeId">>) -> true;
is_primitive(<<"StatusCode">>) -> true;
is_primitive(<<"QualifiedName">>) -> true;
is_primitive(<<"LocalizedText">>) -> true;
is_primitive(<<"ExtensionObject">>) -> true;
is_primitive(<<"DataValue">>) -> true;
is_primitive(<<"Variant">>) -> true;
is_primitive(<<"DiagnosticInfo">>) -> true;
is_primitive(_) -> false.     


-spec encode_field(Type :: binary(), F :: term()) -> binary().
encode_field(<<"Boolean">>, true) -> <<1>>;
encode_field(<<"Boolean">>, false) -> <<0>>;
encode_field(<<"SByte">>, F) ->
    <<F:1/?INT>>;
encode_field(<<"Byte">>, F) ->
    <<F:1/?UINT>>;
encode_field(<<"UInt16">>, F) ->
    <<F:16/?UINT>>;
encode_field(<<"Int16">>, F) ->
    <<F:16/?INT>>;
encode_field(<<"UInt32">>, F) ->
    <<F:32/?UINT>>;
encode_field(<<"Int32">>, F) ->
    <<F:32/?INT>>;
encode_field(<<"UInt64">>, F) ->
    <<F:64/?UINT>>;
encode_field(<<"Int64">>, F) ->
    <<F:64/?INT>>;
encode_field(<<"Float">>, F) ->
    <<F:32/?FLOAT>>;
encode_field(<<"Double">>, F) ->
    <<F:64/?FLOAT>>;
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
    <<0:16/binary>>;
encode_field(<<"ByteString">>, F) ->
    L = byte_size(F),
    <<L:32/?INT,F/binary>>;
encode_field(<<"XmlElement">>, F) ->
    encode_field(<<"ByteString">>, F);
encode_field(<<"NodeId">>, _F) ->
    %% TODO
    <<0>>;
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


%%-record(field_definition, {class :: binary(), fields :: list(tuple(binary(), binary()))}).

get_field_def(<<"OpenSecureChannelRequest">>) ->    
    {<<"structure">>, 
     [{<<"RequestHeader">>, <<"RequestHeader">>},
      {<<"ClientProtocolVersion">>, <<"UInt32">>},
      {<<"RequestType">>, <<"SecurityTokenRequestType">>},
      {<<"SecurityMode">>, <<"MessageSecurityMode">>},
      {<<"ClientNonce">>, <<"ByteString">>},
      {<<"RequestedLifetime">>, <<"UInt32">>}]};
get_field_def(<<"RequestHeader">>) ->
    {<<"structure">>, 
     [{<<"AuthenticationToken">>, <<"NodeId">>},
      {<<"Timestamp">>,<<"DateTime">>},
      {<<"RequestHandle">>,<<"UInt32">>},
      {<<"ReturnDiagnostics">>,<<"UInt32">>},
      {<<"AuditEntryId">>,<<"String">>},
      {<<"TimeoutHint">>,<<"UInt32">>},
      {<<"AdditionalHeader">>,<<"ExtensionObject">>}]};
get_field_def(<<"SecurityTokenRequestType">>) ->
    {<<"enumeration">>,
     [{<<"Issue">>, 0},
      {<<"Renew">>, 1}]}.


encode_obj(Obj = #{<<"type">> := Type}) ->
    case is_primitive(Type) of
	true -> encode_field(Type, Obj);
	false -> 
	    Def = get_field_def(Type),
	    encode_obj(Obj, Def, <<>>)
    end.

encode_obj(_Obj, [], Acc) -> Acc;
encode_obj(Obj = #{<<"fields">> := ObjFields}, [{FieldName,FieldType}|RestFields], Acc) ->
    Field = maps:get(FieldName, ObjFields),
    B = case is_primitive(FieldType) of
	    true -> 
		io:format("encode_field(~p,~p)~n", [FieldType, Field]),
		encode_field(FieldType, Field);
	    false -> 
		io:format("encode_obj(~p)~n", [Field]),
		encode_obj(Field)
	end,    
    NewAcc = <<B/binary,Acc/binary>>,
    encode_obj(Obj, RestFields, NewAcc).

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
