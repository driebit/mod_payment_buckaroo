%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2020 Driebit BV
%% @doc Payment PSP module for Buckaroo

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

-module(mod_payment_buckaroo).

-mod_title("Payments using Buckaroo").
-mod_description("Payments using Payment Service Provider Buckaroo").
-mod_author("Driebit").
-mod_depends([ mod_payment ]).

-author("Driebit <tech@driebit.nl>").

-export([
    init/1,

    observe_payment_psp_request/2,
    observe_payment_psp_view_url/2
    % observe_cancel_subscription_psp_request/2
]).


-include_lib("mod_payment/include/payment.hrl").

init(Context) ->
    lists:map(
        fun({K, V}) ->
            case m_config:get_value(?MODULE, K, Context) of
                undefined ->
                    m_config:set_value(?MODULE, K, V, Context);
                _ ->
                    ok
            end
        end,
        [
            {is_live, <<>>},
            {website_key, <<>>},
            {secret_key, <<>>},
            {webhook_host, <<>>},
            {invoice_nr_prefix, <<"INV">>}
        ]).

%% @doc Payment request, make new payment with Buckaroo, return
%%      payment (buckaroo) details and a redirect uri for the user
%%      to handle the payment.
observe_payment_psp_request(#payment_psp_request{ payment_id = PaymentId, currency = <<"EUR">> }, Context) ->
    m_payment_buckaroo_api:create(PaymentId, Context);
observe_payment_psp_request(#payment_psp_request{}, _Context) ->
    undefined.

observe_payment_psp_view_url(#payment_psp_view_url{ psp_module = ?MODULE, psp_external_id = BuckarooId }, _Context) ->
    {ok, m_payment_buckaroo_api:payment_url(BuckarooId)};
observe_payment_psp_view_url(#payment_psp_view_url{}, _Context) ->
    undefined.

% observe_cancel_subscription_psp_request(#cancel_subscription_psp_request{ user_id = UserId }, Context) ->
%     m_payment_buckaroo_api:cancel_subscription(UserId, Context).
