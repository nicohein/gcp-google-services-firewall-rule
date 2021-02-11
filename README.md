
# Automated Firewall Update for Google Services

The goal is to update the firewall rule that allows all VMs to reach
all google services but not those from google cloud customers.

According to [Google Suport]](https://support.google.com/a/answer/10026322?hl=en)
there are two endpoints from google. One is providing information about all IP ranges announced by Google and
one with all ranges used by google could customers.

While the second is a subset of the first (in terms od IPs not ranges) we need to
 create a diffset which can easily be done using the package `netaddr`.

The ranges are updated daily using cloud scheduler and cloud functions.

Cloud function and scheduler are deployed by administrators of the `bmg-networing` project.

For this to work:
1. a service account used by the cloud function required 'Deployment Manager Editor' permission.
1. and the service account used by the scheduler requires permission to invoke the cloud function.

For HTTP:

```json
{
    "project": "xxxx",
    "network": "xxxx",
    "firewall_rule_name": "allow-egress-google-services-automated",
    "firewall_rule_description": ""
}
```

For PubSub
```json
{
    "data": "a base64 encoded string of the dict above"
}
```
