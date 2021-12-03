# FortiSW-PolicyManager
Centralized software for deploy ACL on Fortinet switches that are managed by a FortiGate

Ingress ACL on a network is recommended, because allways, there are traffic that you really know you don't want in your network. For example, you could block SMTP server, DNS, IPv6 (if you don't use it, of course), SMB (to difficult sharing folders), etc. The aim of that is to block in the perimeter the traffic you are sure you don't want in your network.

This can't be made on GUI, it must be configured on CLI on every switch.

The aim of this script is to let you create an ingress ACL and deploy in all the switches. The only thing you need is the IP of FG, user for FG, and admin password of FortiSwitches.

The key of the process, is to put "PUR_" or "S_PUR" as description of any port that has to added to the policy. If you have your own descriptions, don't worry, just add PUR_ in front. For example: if you have this on a Fortiswitch: port: port1 description: "port_of_user1", you have to do that: port: port1 description: "PUR_port_of_user1". 
<p>
  <p>
Rememeber that, description , is changed on Fortigate:
<p>
  <p>
FG>config switch-controller managed-switch<p>
FG>edit <SN_SWITCH><p>
FG>config ports<p>
FG>edit port1<p>
FG>set description PUR_<p>
FG>next<p>
<p>
<p>
<p>


How to use:


<b>/usr/bin/python3.9 -W ignore politica_us_raonable.py >> logg.out </b>

-W is used as usually FG have a autosigned certificate. Using -W ignore, don't warn you.

on <b>politica_us_raonable.conf</b>, is stored the IP of FG, users, and passwords. instead of store password, I recommend to use "ASK", cause this ask every execution the password, and you don't store passwords on files.

on <b>custom_services</b> you can define your own policies, (The default policies on FSW are generic)

on <b>politica_us_raonable_general</b>, is where you define the policy 

For example:
<r>
{"json":{"id":"100","ingress-interface":[%],"classifier":{"src-mac":"d0:03:4b:d2:e6:44"},"action":{"drop":"enable"}}}

This block a MAC in all the ports with policy enabled.
<p>
on <b>politica_us_raonable_general_servidors</b>, is where you define the policy of servers. (less restrictive than general).

<p>
Finally, on politica_us_raonable.sh, there are a bash shell. This must fit your system (PATH, and user). 
<br>
