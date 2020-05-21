%% @copyright 2020 Driebit BV
%% @doc Buckaroo redirect the user with a POST to this controller
%%      after a payment has been done at their HTML gateway.
%%      This controller processes the payment status and then redirects
%%      to either the payment_psp_done or payment_psp_cancel page.

%% Copyright 2012 Marc Worrrell
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

% Fields are documented here: https://support.buckaroo.nl/categorieën/transacties/push-berichten
%
% Sample post:
%
% [{"payment_nr","zozqioczidkgfdvlrxvrjrshrzxbuzkm"},
%  {"z_language","nl"},
%  {"brq_amount","1.00"},
%  {"brq_currency","EUR"},
%  {"brq_customer_name","J. de TÃ¨ster"},
%  {"brq_description","Test"},
%  {"brq_invoicenumber","INV0000.0000.0008"},
%  {"brq_payer_hash",
%   "1892294f6d278d65ec5425896418d6ae62146741f03393654959febe6e73d5c822c461c521761c3732b4f96dc7a7fc57eba7aac0a736fb948861ce2081c79fba"},
%  {"brq_payment","8586EFA60B5A41E29B4CF002227CC68F"},
%  {"brq_payment_method","ideal"},
%  {"brq_SERVICE_ideal_consumerBIC","RABONL2U"},
%  {"brq_SERVICE_ideal_consumerIBAN","NL44RABO0123456789"},
%  {"brq_SERVICE_ideal_consumerIssuer","Handelsbanken"},
%  {"brq_SERVICE_ideal_consumerName","J. de TÃ¨ster"},
%  {"brq_SERVICE_ideal_transactionId","0000000000000001"},
%  {"brq_statuscode","190"},
%  {"brq_statuscode_detail","S001"},
%  {"brq_statusmessage","Transaction successfully processed"},
%  {"brq_test","true"},
%  {"brq_timestamp","2020-04-30 17:56:49"},
%  {"brq_transactions","0280343636F047079E523F1EE71959BD"},
%  {"brq_websitekey","CQxkFU644M"},
%  {"brq_signature","3d8f2ab0039e94eb9901dc80d44207f921abd1a3"}]

-module(controller_buckaroo_redirect).

-export([
    init/1,
    service_available/2,
    allowed_methods/2,
    resource_exists/2,
    previously_existed/2,
    moved_temporarily/2
    ]).

-include_lib("controller_webmachine_helper.hrl").
-include_lib("zotonic.hrl").

init(DispatchArgs) -> {ok, DispatchArgs}.

service_available(ReqData, DispatchArgs) when is_list(DispatchArgs) ->
    Context  = z_context:new(ReqData, ?MODULE),
    Context1 = z_context:set(DispatchArgs, Context),
    Context2 = z_context:ensure_qs(Context1),
    ?WM_REPLY(true, Context2).

allowed_methods(ReqData, Context) ->
    {['POST'], ReqData, Context}.

resource_exists(ReqData, Context) ->
    {false, ReqData, Context}.

previously_existed(ReqData, Context) ->
    {true, ReqData, Context}.

moved_temporarily(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    case is_signature_ok(Context1) of
        false ->
            redirect(payment_psp_cancel, Context1);
        true ->
            StatusCode = z_convert:to_integer(z_context:get_q("brq_statuscode", Context1)),
            Timestamp = z_context:get_q("brq_timestamp", Context1),
            PspId = z_context:get_q("brq_transactions", Context1),
            set_status(PspId, StatusCode, Timestamp, Context1),
            lager:info("Buckaroo controller found PAYMENT STATUS ~p", [ StatusCode ]),
            case StatusCode of
                190 ->
                    % Payment done
                    redirect(payment_psp_done, Context1);
                790 ->
                    % Pending (on customer)
                    redirect(payment_psp_done, Context1);
                791 ->
                    % Pending (on redirect to website)
                    redirect(payment_psp_done, Context1);
                793 ->
                    % Hold (waiting for funds)
                    redirect(payment_psp_done, Context1);
                490 ->
                    % Failed (Mislukt)
                    redirect(payment_psp_done, Context1);
                690 ->
                    % Failed (afgewezen)
                    redirect(payment_psp_done, Context1);
                890 ->
                    % Canceled by customer
                    redirect(payment_psp_cancel, Context1);
                _ ->
                    % Probably canceled
                    redirect(payment_psp_cancel, Context1)
            end
    end.

set_status(PspId, StatusCode, Timestamp, Context) ->
    DateTime = z_datetime:to_datetime(Timestamp),
    case m_payment:get_by_psp(mod_payment_buckaroo, PspId, Context) of
        {ok, Payment} ->
            Id = proplists:get_value(id, Payment),
            m_payment_buckaroo_api:update_payment_status(Id, StatusCode, DateTime, Context);
        {error, _} = Error ->
            Error
    end.

redirect(Dispatch, Context) ->
    Args = [
        {payment_nr, z_context:get_q("payment_nr", Context)}
    ],
    Location = z_context:abs_url(
                    z_convert:to_binary( z_dispatcher:url_for(Dispatch, Args, Context) ),
                    Context),
    Location1 = z_convert:to_list( z_convert:to_binary(Location) ),
    Context1 = z_context:set_resp_header("Location", Location1, Context),
    ?WM_REPLY({halt, 302}, Context1).


is_signature_ok(Context) ->
    Args = [
            {
                z_convert:to_binary(z_string:to_lower(K)),
                K,
                V
            }
            || {K,V} <- z_context:get_q_all_noz(Context), not is_atom(K)
           ],
    Args1 = lists:filter(fun is_brq_sign_arg/1, Args),
    SigString = sig_string(Args1),
    OurSig = z_convert:to_binary(sig(SigString, Context)),
    SigQ = q_sig(Args),
    case OurSig of
        SigQ ->
            true;
        _Other ->
            lager:error("Buckaroo controller failed signature ~p (expected ~p) on ~p",
                        [ OurSig, SigQ, Args1 ]),
            false
    end.

is_brq_sign_arg({<<"brq_signature">>, _, _}) -> false;
is_brq_sign_arg({<<"brq_", _/binary>>, _, _}) -> true;
is_brq_sign_arg({<<"cust_", _/binary>>, _, _}) -> true;
is_brq_sign_arg({<<"add_", _/binary>>, _, _}) -> true;
is_brq_sign_arg(_) -> false.

q_sig(Args) ->
    {<<"brq_signature">>, _, Sig} = lists:keyfind(<<"brq_signature">>, 1, Args),
    z_convert:to_binary(z_string:to_lower(Sig)).

sig_string(Qs) ->
    Qs1 = lists:sort(Qs),
    iolist_to_binary([ [
            z_convert:to_binary(K),
            $=,
            z_convert:to_binary(V)
        ] || {_, K,V} <- Qs1 ]).

sig(SigString, Context) ->
    Data = [
        SigString,
        z_convert:to_binary(m_config:get_value(mod_payment_buckaroo, secret_key, Context))
    ],
    Sha = crypto:hash(sha, Data),
    z_string:to_lower(iolist_to_binary(z_url:hex_encode(Sha))).


