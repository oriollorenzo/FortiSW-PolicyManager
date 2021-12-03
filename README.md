# FortiSW-PolicyManager
Centralized software for deploy ACL on Fortinet switches that are managed by a FortiGate

How to use:

on politica_us_raonable.conf, is stored the IP of FG, users, and passwords. instead of store password, I recommend to use "ASK", cause this ask every execution the password, and you don't store passwords on files.

on custom_services you can define your own policies, (The default policies on FSW are generic)

on politica_us_raonable_general, is where you define the policy 

For example:

{"json":{"id":"100","ingress-interface":[%],"classifier":{"src-mac":"d0:03:4b:d2:e6:44"},"action":{"drop":"enable"}}}

This is a block for that mac address. This permits to block a MAC in all the ports with policy enabled.

on politica_us_raonable_general, is where you define the policy of servers. (less restrictive than general).

