%% @copyright 2020 Driebit BV
%% @doc API interface and (push) state handling for Buckaroo PSP

%% Copyright 2020 Driebit BV
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(m_payment_buckaroo_api).

-export([
    create/2,
    webhook_data/2,

    is_test/1,
    api_key/1,
    webhook_url/2,
    payment_url/1,

    is_valid_authorization_header/2,
    update_payment_status/4
    ]).

-export([
    api_test/1,
    invoice_nr/2,
    test/1
]).

-include("zotonic.hrl").
-include("zotonic_release.hrl").
-include("mod_payment/include/payment.hrl").

-define(BUCKAROO_API_URL, "https://checkout.buckaroo.nl/").
-define(BUCKAROO_TEST_API_URL, "https://testcheckout.buckaroo.nl/").


-define(TIMEOUT_REQUEST, 10000).
-define(TIMEOUT_CONNECT, 5000).


test(Context) ->
    PaymentRequest = #payment_request{
        key = undefined,
        user_id = undefined,
        amount = 1.0,
        currency = <<"EUR">>,
        language = z_context:language(Context),
        description_html = <<"Test">>,
        is_qargs = false,
        recurring = false,
        extra_props = [
            {email, <<"marc@worrell.nl">>},
            {name_surname, <<"Pietersen">>}
        ]
    },
    case z_notifier:first(PaymentRequest, Context) of
        #payment_request_redirect{ redirect_uri = RedirectUri } ->
            {ok, RedirectUri};
        Other ->
            Other
    end.


api_test(Context) ->
    Args = #{
        <<"AmountDebit">> => 1.00,
        <<"Currency">> => <<"EUR">>,
        <<"Invoice">> => <<"test00001">>,
        <<"Description">> => <<"This is a test">>,
        <<"ContinueOnIncomplete">> => 1,
        <<"Services">> => #{
            <<"ServiceList">> => [
            ]
        }
    },
    api_call(post, "json/Transaction", Args, en, Context).


%% @doc Create a new payment with Buckaroo
%%      Docs: https://dev.buckaroo.nl/Apis
%%            https://testcheckout.buckaroo.nl/json/Docs/Api/POST-json-Transaction
%%      Status codes: https://support.buckaroo.nl/categorieën/transacties/status
create(PaymentId, Context) ->
    {ok, Payment} = m_payment:get(PaymentId, Context),
    case proplists:get_value(currency, Payment) of
        <<"EUR">> = Currency ->
            PaymentNr = proplists:get_value(payment_nr, Payment),
            RedirectUrl = z_context:abs_url(
                z_dispatcher:url_for(
                    buckaroo_payment_redirect,
                    [ {payment_nr, PaymentNr} ],
                    Context),
                Context),
            WebhookUrl = webhook_url(proplists:get_value(payment_nr, Payment), Context),
            Amount = proplists:get_value(amount, Payment),
            % AmountS = z_convert:to_binary(io_lib:format("~.2f", [ abs(Amount) ])),
            Args = case Amount >= 0 of
                true ->
                    #{
                        <<"AmountDebit">> => Amount
                    };
                false ->
                    #{
                        <<"AmountCredit">> => abs(Amount)
                    }
            end,
            InvoiceNr = invoice_nr(Payment, Context),
            Args1 = Args#{
                <<"Currency">> => Currency,
                <<"Description">> => valid_description( proplists:get_value(description, Payment) ),
                <<"Invoice">> => InvoiceNr,
                <<"ReturnURL">> => z_convert:to_binary(RedirectUrl),
                <<"PushURL">> => z_convert:to_binary(WebhookUrl),
                <<"ContinueOnIncomplete">> => 1,
                <<"Services">> => #{
                    <<"ServiceList">> => [
                    ]
                },
                <<"CustomParameters">> => [
                    #{
                        <<"Name">> => <<"PaymentNr">>,
                        <<"Value">> => z_convert:to_binary(PaymentNr)
                    }
                ]
            },
            Args2 = case proplists:get_value(recurring, Payment) of
                true ->
                    Args1#{
                        <<"StartRecurrent">> => true
                    };
                false ->
                    Args1
            end,
            Args3 = add_peer(Args2, Context),
            Args4 = add_user_agent(Args3, Context),
            Language = proplists:get_value(language, Payment),
            case api_call(post, "json/Transaction", Args4, Language, Context) of
                {ok, #{ <<"Key">> := BuckarooKey,
                        <<"RequiredAction">> := #{
                                <<"Name">> := <<"Redirect">>,
                                <<"RedirectURL">> := PaymentUrl
                            }
                        } = JSON} ->
                    m_payment_log:log(
                        PaymentId,
                        <<"CREATED">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {psp_external_log_id, BuckarooKey},
                            {description, <<"Created Mollie payment ", BuckarooKey/binary>>},
                            {request_result, JSON}
                        ],
                        Context),
                    {ok, #payment_psp_handler{
                        psp_module = mod_payment_buckaroo,
                        psp_external_id = BuckarooKey,
                        psp_data = JSON,
                        redirect_uri = PaymentUrl
                    }};
                {ok, #{
                        <<"RequestErrors">> := _,
                        <<"Status">> := #{
                            <<"Code">> := #{
                                <<"Code">> := StatusCode,
                                <<"Description">> := StatusDescription
                            }
                        }
                    } = JSON} ->
                    m_payment_log:log(
                        PaymentId,
                        <<"ERROR">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {description, "API Error creating order with Buckaroo"},
                            {request_result, JSON},
                            {request_args, Args}
                        ],
                        Context),
                    lager:error("API error creating buckaroo payment for #~p: ~p \"~s\"",
                                [PaymentId, StatusCode, StatusDescription]),
                    {error, {status, StatusCode}};
                {ok, JSON} ->
                    m_payment_log:log(
                        PaymentId,
                        <<"ERROR">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {description, "API Error creating order with Buckaroo"},
                            {request_result, JSON},
                            {request_args, Args}
                        ],
                        Context),
                    lager:error("API error creating buckaroo payment for #~p: unknown json ~p",
                                [PaymentId, JSON]),
                    {error, json};
                {error, Error} ->
                    m_payment_log:log(
                        PaymentId,
                        <<"ERROR">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {description, "API Error creating order with Buckaroo"},
                            {request_result, Error},
                            {request_args, Args}
                        ],
                        Context),
                    lager:error("API error creating buckaroo payment for #~p: ~p", [PaymentId, Error]),
                    {error, Error}
            end;
        Currency ->
            lager:error("Buckaroo payment request with non EUR currency: ~p", [Currency]),
            {error, {currency, only_eur}}
    end.

valid_description(<<>>) -> <<"Payment">>;
valid_description(undefined) -> <<"Payment">>;
valid_description(D) when is_binary(D) -> D.


%% @doc Add the peer IP address to the request, used for fraud detection
add_peer(Args, Context) ->
    case m_req:get(peer, Context) of
        undefined -> Args;
        IP ->
            case inet:parse_address(IP) of
                {ok, {_, _, _, _}} ->
                    Args#{
                        <<"ClientIP">> => #{
                            <<"Type">> => 0,
                            <<"Address">> => z_convert:to_binary(IP)
                        }
                    };
                {ok, _} ->
                    Args#{
                        <<"ClientIP">> => #{
                            <<"Type">> => 1,
                            <<"Address">> => z_convert:to_binary(IP)
                        }
                    };
                {error, _} ->
                    Args
            end
    end.

%% @doc Add the user-agent to the request, used for fraud detection
add_user_agent(Args, Context) ->
    case m_req:get(user_agent, Context) of
        undefind -> Args;
        UA ->
            Args#{
                <<"ClientUserAgent">> => z_convert:to_binary(UA)
            }
    end.

%% @doc Return the invoice number for this payment.
-spec invoice_nr( proplists:proplist(), z:context() ) -> binary().
invoice_nr(Payment, Context) ->
    InvNr = case proplists:get_value(props, Payment) of
        Props when is_list(Props) ->
            proplists:get_value(invoice_nr, Props);
        Props when is_map(Props) ->
            maps:get(invoice_nr, Props, undefined);
        _ ->
            undefined
    end,
    case z_utils:is_empty(InvNr) of
        true ->
            PaymentId = proplists:get_value(id, Payment),
            Prefix = m_config:get_value(mod_payment_buckaroo, invoice_nr_prefix, <<"INV">>, Context),
            iolist_to_binary([
                Prefix,
                io_lib:format("~4..0B", [ (PaymentId div 100000000) rem 10000 ]),
                ".",
                io_lib:format("~4..0B", [ (PaymentId div 10000) rem 10000 ]),
                ".",
                io_lib:format("~4..0B", [ PaymentId rem 10000 ])
            ]);
        false ->
            z_convert:to_binary(InvNr)
    end.


%% @doc Return the url for the callbacks from Buckaroo.
%%      Allow special hostname for the webhook, useful for testing.
-spec webhook_url( binary(), z:context() ) -> binary().
webhook_url(PaymentNr, Context) ->
    Path = z_dispatcher:url_for(buckaroo_payment_webhook, [ {payment_nr, PaymentNr} ], Context),
    case m_config:get_value(mod_payment_buckaroo, webhook_host, Context) of
        <<"http", _/binary>> = Host -> <<Host/binary, Path/binary>>;
        _ -> iolist_to_binary( z_context:abs_url(Path, Context) )
    end.


%% @doc Return the URL to the status page on the buckaroo dashboard
-spec payment_url(binary() | string()) -> binary().
payment_url(BuckarooKey) ->
    iolist_to_binary([
        "https://plaza.buckaroo.nl/Transaction/Transactions/Details",
        "?transactionKey=", z_convert:to_binary(BuckarooKey)
    ]).


%% @doc Handle the pushed JSON from the webhook.
-spec webhook_data(map(), z:context()) -> ok | {error, notfound|term()}.
webhook_data(#{ <<"Transaction">> := #{ <<"Key">> := ExtId } = JSON }, Context) ->
    case m_payment:get_by_psp(mod_payment_buckaroo, ExtId, Context) of
        {ok, Payment} ->
            PaymentId = proplists:get_value(id, Payment),
            case JSON of
                #{
                    <<"Status">> := #{
                        <<"Code">> := #{
                            <<"Code">> := StatusCode,
                            <<"Description">> := StatusDescription
                        },
                        <<"DateTime">> := DateTime
                    }
                } ->
                    lager:info("Payment PSP Buckaroo received status ~p \"~s\" for payment #~p",
                               [ StatusCode, StatusDescription, PaymentId ]),
                    m_payment_log:log(
                        PaymentId,
                        <<"STATUS">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {description, "Webhook push event"},
                            {request_result, JSON}
                        ],
                        Context),
                    DT = z_datetime:to_datetime(DateTime),
                    update_payment_status(PaymentId, StatusCode, DT, Context);
                _ ->
                    lager:error("Payment PSP Buckaroo received non-status push for payment #~p: ~p",
                               [ PaymentId, JSON ]),
                    m_payment_log:log(
                        PaymentId,
                        <<"ERROR">>,
                        [
                            {psp_module, mod_payment_buckaroo},
                            {description, "Webhook push event without Status"},
                            {request_result, JSON}
                        ],
                        Context),
                    {error, no_status_code}
            end;
        {error, notfound} ->
            lager:error("Payment PSP Mollie webhook call with unknown id ~p", [ExtId]),
            {error, notfound};
        {error, _} = Error ->
            lager:error("Payment PSP Mollie webhook call with id ~p, fetching payment error: ~p", [ExtId, Error]),
            Error
    end;
webhook_data(JSON, _Context) ->
    lager:error("Payment PSP Buckaroo webhook JSON without \"Key\": ~p", [ JSON ]),
    {error, nokey}.


% Status is one of: open cancelled expired failed pending paid paidout refunded charged_back
% https://support.buckaroo.nl/categorieën/transacties/status
update_payment_status(PaymentId, 190, DT, Context) ->
    % Succes: De transactie is geslaagd en de betaling is ontvangen / goedgekeurd
    mod_payment:set_payment_status(PaymentId, paid, DT, Context);
update_payment_status(PaymentId, 490, DT, Context) ->
    % Mislukt: De transactie is mislukt.
    mod_payment:set_payment_status(PaymentId, failed, DT, Context);
update_payment_status(PaymentId, 491, DT, Context) ->
    % Validatie mislukt: Het transactieverzoek bevatte fouten en kon niet goed verwerkt worden.
    mod_payment:set_payment_status(PaymentId, failed, DT, Context);
update_payment_status(PaymentId, 492, DT, Context) ->
    % Technische fout: Door een technische fout kon de transactie niet worden afgerond.
    mod_payment:set_payment_status(PaymentId, failed, DT, Context);
update_payment_status(PaymentId, 690, DT, Context) ->
    % De transactie is afgewezen door de (derde) payment provider.
    mod_payment:set_payment_status(PaymentId, cancelled, DT, Context);
update_payment_status(PaymentId, 790, DT, Context) ->
    % In afwachting van invoer: De transactie is in de wacht, terwijl de payment
    % engine staat te wachten op de inbreng van de consument.
    mod_payment:set_payment_status(PaymentId, pending, DT, Context);
update_payment_status(PaymentId, 791, DT, Context) ->
    % In afwachting van verwerking: de transactie wordt verwerkt. Vaak wordt er
    % gewacht voor de consument om terug te keren van een website van derden,
    % die nodig is om de transactie te voltooien.
    mod_payment:set_payment_status(PaymentId, pending, DT, Context);
update_payment_status(PaymentId, 792, DT, Context) ->
    % In afwachting van de consument: de consument moet nog een actie ondernemen,
    % zoals handmatig geld overschrijven vanuit zijn bankomgeving bij een Overboeking.
    mod_payment:set_payment_status(PaymentId, pending, DT, Context);
update_payment_status(PaymentId, 793, DT, Context) ->
    % De transactie staat on-hold.
    mod_payment:set_payment_status(PaymentId, pending, DT, Context);
update_payment_status(PaymentId, 890, DT, Context) ->
    % Geannuleerd door Gebruiker: De transactie is geannuleerd door de klant.
    mod_payment:set_payment_status(PaymentId, cancelled, DT, Context);
update_payment_status(PaymentId, 891, DT, Context) ->
    % Geannuleerd door Merchant: De merchant heeft de transactie geannuleerd.
    mod_payment:set_payment_status(PaymentId, cancelled, DT, Context);
update_payment_status(PaymentId, Code, _DT, _Context) ->
    lager:error("Payment PSP Buckaroo received unknown status push ~p for payment #~p",
                [ Code, PaymentId ]),
    ok.


api_call(Method, Endpoint, Args, undefined, Context) ->
    api_call(Method, Endpoint, Args, z_context:language(Context), Context);
api_call(Method, Endpoint, Args, Language, Context) ->
    case api_key(Context) of
        {ok, {WebSiteKey, SecretKey}} ->
            Body = jsx:encode(Args),
            Url = api_url(Context) ++ z_convert:to_list(Endpoint),
            Auth = authorization(WebSiteKey, SecretKey, Method, Url, Body),
            Hs = [
                {"Authorization", z_convert:to_list(Auth)},
                {"Culture", z_convert:to_list(Language)},
                {"Software", software()}
            ],
            Request = case Method of
                get ->
                    {Url, Hs};
                _ ->
                    {Url, Hs, "application/json", Body}
            end,
            lager:info("Making API call to Buckaroo: ~p~n", [Request]),
            case httpc:request(
                Method, Request,
                [
                    {autoredirect, true},
                    {relaxed, false},
                    {timeout, ?TIMEOUT_REQUEST},
                    {connect_timeout, ?TIMEOUT_CONNECT}
                ],
                [
                    {sync, true},
                    {body_format, binary}
                ])
            of
                {ok, {{_, X20x, _}, Headers, Payload}} when ((X20x >= 200) and (X20x < 400)) ->
                    case proplists:get_value("content-type", Headers) of
                        undefined ->
                            {ok, Payload};
                        ContentType ->
                            case binary:match(list_to_binary(ContentType), <<"json">>) of
                                nomatch ->
                                    {ok, Payload};
                                _ ->
                                    Props = jsx:decode(Payload, [return_maps]),
                                    {ok, Props}
                            end
                    end;
                {ok, {{_, Code, _}, Headers, Payload}} ->
                    lager:error("Buckaroo returns ~p: ~p ~p", [ Code, Payload, Headers]),
                    {error, Code};
                {error, _} = Error ->
                    Error
            end;
        {error, notfound} ->
            {error, api_key_not_set}
    end.

software() ->
    binary_to_list(
        jsx:encode(#{
            <<"PlatformName">> => <<"Zotonic">>,
            <<"PlatformVersion">> => z_convert:to_binary(?ZOTONIC_VERSION),
            <<"ModuleSupplier">> => <<"Driebit">>,
            <<"ModuleName">> => <<"mod_payment_mollie">>,
            <<"ModuleVersion">> => <<>>
        })
    ).

%% @doc Check if the authorization header of the current request is valid.
-spec is_valid_authorization_header( binary(), z:context() ) -> boolean().
is_valid_authorization_header(Body, Context) ->
    case api_key(Context) of
        {ok, {WebSiteKey, SecretKey}} ->
            Method = m_req:get(method, Context),
            Url = iolist_to_binary([
                    "https://",
                    m_req:get(host, Context),
                    m_req:get(raw_path, Context)
                ]),
            Hdr = z_convert:to_binary( z_context:get_req_header("authorization", Context) ),
            case Hdr of
                <<"hmac ", Hash/binary>> ->
                    case binary:split(Hash, <<":">>, [global]) of
                        [ WebSiteKey, Sig, Nonce, Timestamp ] ->
                            case calc_sig(WebSiteKey, SecretKey, Method,
                                          Url, Body, Nonce, Timestamp)
                            of
                                Sig ->
                                    true;
                                Expected ->
                                    lager:error("Buckaroo Sig mismatch expected ~p, got ~p",
                                                [ Expected, Sig ]),
                                    false
                            end;
                        _ ->
                            lager:error("Buckaroo key pattern mismatch: ~p",
                                        [ Hash ]),
                            false
                    end;
                _ ->
                    lager:error("Buckaroo authorization header mismatch: ~p",
                                [ Hdr ]),
                    false
            end;
        {error, _} ->
            false
    end.

authorization(WebSiteKey, SecretKey, Method, Url, Body) ->
    Nonce = z_ids:id(16),
    Timestamp = z_datetime:timestamp(),
    Sig = calc_sig(WebSiteKey, SecretKey, Method, Url, Body, Nonce, Timestamp),
    iolist_to_binary([
        "hmac ",
        WebSiteKey, ":",
        Sig, ":",
        Nonce, ":",
        integer_to_binary(Timestamp)
    ]).

calc_sig(WebSiteKey, SecretKey, Method, Url, Body, Nonce, Timestamp) ->
    BodyMD5 = crypto:hash(md5, Body),
    BodyHash = base64:encode(BodyMD5),
    SigData = [
        WebSiteKey,
        case Method of
            post -> "POST";
            get -> "GET";
            'POST' -> "POST";
            'GET' -> "GET"
        end,
        auth_uri(Url),
        z_convert:to_binary(Timestamp),
        Nonce,
        BodyHash
    ],
    Sig = crypto:hmac(sha256, SecretKey, SigData),
    base64:encode(Sig).

auth_uri("https://" ++ Uri) ->
    z_string:to_lower(z_url:url_encode(Uri));
auth_uri("http://" ++ Uri) ->
    z_string:to_lower(z_url:url_encode(Uri));
auth_uri(<<"https://", Uri/binary>>) ->
    z_string:to_lower(z_url:url_encode(Uri));
auth_uri(<<"http://", Uri/binary>>) ->
    z_string:to_lower(z_url:url_encode(Uri)).

is_test(Context) ->
    not z_convert:to_bool( m_config:get_value(mod_payment_buckaroo, is_live, Context) ).

api_url(Context) ->
    case is_test(Context) of
        true -> ?BUCKAROO_TEST_API_URL;
        false -> ?BUCKAROO_API_URL
    end.

-spec api_key(z:context()) -> {ok, {binary(), binary()}} | {error, notfound}.
api_key(Context) ->
    WebsiteKey = m_config:get_value(mod_payment_buckaroo, website_key, Context),
    SecretKey = m_config:get_value(mod_payment_buckaroo, secret_key, Context),
    case z_utils:is_empty(WebsiteKey) or z_utils:is_empty(SecretKey) of
        true ->
            {error, notfound};
        false ->
            {ok, {WebsiteKey, SecretKey}}
    end.
