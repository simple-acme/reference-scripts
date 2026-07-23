# Reference scripts
simple-acme can run scripts (PowerShell/sh) to extend its functionality where native support is missing. 
Because of the general risk of running scripts that you find on the internet and the vast complexity that 
can lurk in a Windows/Office (enterprise) environments, we highly recommend that you carefully review and
test any code that you download from this repository.

**These scripts are provided as-is without any warranties or support.**

## Installation scripts
Scripts used to install new certificates in third-party software that is not IIS. 
Examples are Exchange, RDS, SQL Server, etc.
Documentation: https://simple-acme.com/reference/plugins/installation/script

## Validation scripts
Scripts used to validate with DNS service providers that do not have a native plugin (yet)
Documentation: https://simple-acme.com/reference/plugins/validation/dns/script

## Notification scripts
Scripts used to notify yourself or your team about successes or failures. Documentation: https://simple-acme.com/manual/notifications

## Execution scripts
Scripts called before or after the execution of a renewal, e.g. to temporarily open port 80 on the firewall. Documentation: https://simple-acme.com/reference/settings#DefaultPreExecutionScript
