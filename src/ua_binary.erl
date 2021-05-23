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
    <<0>>;
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


%% TODO this should be replaced with an ETS table. {type, definition) type :: {ua_prim, ua_struct, ua_enum}
get_field_def(<<"OpenSecureChannelRequest">>) ->    
    {ua_struct, 
     [{<<"RequestHeader">>, <<"RequestHeader">>},
      {<<"ClientProtocolVersion">>, <<"UInt32">>},
      {<<"RequestType">>, <<"SecurityTokenRequestType">>},
      {<<"SecurityMode">>, <<"MessageSecurityMode">>},
      {<<"ClientNonce">>, <<"ByteString">>},
      {<<"RequestedLifetime">>, <<"UInt32">>}]};
get_field_def(<<"RequestHeader">>) ->
    {ua_struct, 
     [{<<"AuthenticationToken">>, <<"NodeId">>},
      {<<"Timestamp">>,<<"DateTime">>},
      {<<"RequestHandle">>,<<"UInt32">>},
      {<<"ReturnDiagnostics">>,<<"UInt32">>},
      {<<"AuditEntryId">>,<<"String">>},
      {<<"TimeoutHint">>,<<"UInt32">>},
      {<<"AdditionalHeader">>,<<"ExtensionObject">>}]};
get_field_def(<<"SecurityTokenRequestType">>) ->
    {ua_enum,
     [{<<"Issue">>, 0},
      {<<"Renew">>, 1}]};
get_field_def(<<"MessageSecurityMode">>) ->
    {ua_enum,
     [{<<"Blah">>, 0},
      {<<"Blah1">>, 1},
      {<<"Blah2">>, 2},
      {<<"Blah3">>, 0}]};
get_field_def(<<"Boolean">>) -> ua_prim;
get_field_def(<<"SByte">>) -> ua_prim;
get_field_def(<<"Byte">>) -> ua_prim;
get_field_def(<<"UInt16">>) -> ua_prim;
get_field_def(<<"Int16">>) -> ua_prim;
get_field_def(<<"UInt32">>) -> ua_prim;
get_field_def(<<"Int32">>) -> ua_prim;
get_field_def(<<"UInt64">>) -> ua_prim;
get_field_def(<<"Int64">>) -> ua_prim;
get_field_def(<<"Float">>) -> ua_prim;
get_field_def(<<"Double">>) -> ua_prim;
get_field_def(<<"String">>) -> ua_prim;
get_field_def(<<"DateTime">>) -> ua_prim;
get_field_def(<<"GUID">>) -> ua_prim;
get_field_def(<<"ByteString">>) -> ua_prim;
get_field_def(<<"XmlElement">>) -> ua_prim;
get_field_def(<<"NodeId">>) -> ua_prim;
get_field_def(<<"ExpandedNodeId">>) -> ua_prim;
get_field_def(<<"StatusCode">>) -> ua_prim;
get_field_def(<<"QualifiedName">>) -> ua_prim;
get_field_def(<<"LocalizedText">>) -> ua_prim;
get_field_def(<<"ExtensionObject">>) -> ua_prim;
get_field_def(<<"DataValue">>) -> ua_prim;
get_field_def(<<"Variant">>) -> ua_prim;
get_field_def(<<"DiagnosticInfo">>) -> ua_prim;
get_field_def(_) -> false.     




encode_obj(Obj = #{<<"type">> := Type}) ->
    encode_obj(Obj, Type).
encode_obj(Obj, Type) ->
    case get_field_def(Type) of
	ua_prim -> encode_field(Type, Obj);
	{Class, Def} -> encode_obj(Obj, Class, Def, <<>>);
	false -> io:format("Unknown type ~p~n", [Type]),
		 exit(unknown_type)
    end.
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
