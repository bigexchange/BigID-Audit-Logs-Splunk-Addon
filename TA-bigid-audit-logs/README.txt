This add-on takes audit logs from your BigID instance and ingest them into splunk.

For this you need to provide the Base URL for your BigID instance (E.g. https://sandbox.bigid.tools), and the name and value of the Token to authenticate with BigID.

After adding a new Data Input with these values, you should be able to see the results by searching by 'sourcetype="bigid:audit:logs"'.
