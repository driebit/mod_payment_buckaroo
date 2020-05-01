Buckaroo payments for Zotonic
=============================

This is a Payment Service Provider (PSP) module for mod_payment:

    https://github.com/driebit/mod_payment

This module interfaces mod_payment to the PSP Buckaroo (https://buckaroo.nl/)


Configuration
-------------

The following configuration keys can be set:

 * `mod_payment_buckaroo.is_live` set this to `1` to switch from the test transactions to
   the live Buckaroo systems. Default the module is set up to use test transactions.

 * `mod_payment_buckaroo.website_key` the website API key for Buckaroo API requests. You
   can find this key on https://plaza.buckaroo.nl/Configuration/WebSite/Index/

 * `mod_payment_buckaroo.secret_key` the secret API key for Buckaroo API requests. This is
   the key that can be set at https://plaza.buckaroo.nl/Configuration/Merchant/SecretKey

 * `mod_payment_buckaroo.invoice_nr_prefix` the payment-id is used as the buckaroo invoice
   number. It is prefixed with this config key, which defaults to `"INV"`. The payment-id
   is formatted as: `"INV0000.0000.0012"`


Webhook and Redirect URLs
-------------------------

The webhook does not need to be installed at Buckaroo, a push-url is automatically added
to every transaction request.

Same for the Redirect urls, they are also generated for every transaction and don't need
to be configured at Buckaroo.

Note that the webhook must be accessible on one of the following ports: 22; 44; 80; 8443;
8787; 8880; 8888. As Buckaroo does not support any other ports. The protocol can be
http: or https: (no self-signed certs).

Development configuration
-------------------------

 * `mod_payment_buckaroo.webhook_host` this should be the host (with `http:` prefix)
   where Buckaroo should send the webhook messages. Only use this if your (development)
   site is reachable from the outside via a different URL than the configured hostnames.

Test data
---------

If the config key `mod_payment_buckaroo.is_live` is not set then the buckaroo test url
will be used and the following bank and credit cards can be used for testing:

https://support.buckaroo.nl/categorieën/integratie/test-gegevens

