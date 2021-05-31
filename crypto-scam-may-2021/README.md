## Background

Received an email from "crypto.com" saying that my email address has not been verified. ![Email from attacker](images/email.png)

## Quick Analysis

The email has an attachment: crypto.pdf, 260 bytes according to outlook. The sender is `oansoivnras@officetabletas.onmicrosoft.com`, with a name of `Crypto.com`. My email address was CC'ed. 

The email was sent using `.onmicrosoft.com` domain, which appears to be a Microsoft Office 365 client with thename `officetabletas`. 

The webpage has a button that send you to a link `http://seo.get-pack.ir/redirect.php?url=http://ujam3vxb.a0sa.org/?ty007`which will redirect you to a malicious URL `http://ujam3vxb.a0sa.org/?ty007`. 


A quick `whois` check shows the following information:

```
% Information related to 'get-pack.ir'


domain:		get-pack.ir
ascii:		get-pack.ir
remarks:	(Domain Holder) mohammad javad karimi
remarks:	(Domain Holder Address) forooghi st., vali asr St., No. 18,, Esfahan, Esfahan, IR
holder-c:	mk794-irnic
admin-c:	mk794-irnic
tech-c:		mk794-irnic
bill-c:		as52-irnic
nserver:	ns.netafraz.com
nserver:	ns2.netafraz.com
last-updated:	2021-05-17
expire-date:	2026-11-21
source:		IRNIC # Filtered

nic-hdl:	mk794-irnic
person:		mohammad javad karimi
e-mail:		mjk1900@gmail.com
address:	forooghi st., vali asr St., No. 18,, Esfahan, Esfahan, IR
phone:		+983113352320
source:		IRNIC # Filtered

nic-hdl:	as52-irnic
org:		AsanRayan Jahan Gostar Co.
e-mail:		admin@asanrayan.com
source:		IRNIC # Filtered
```

The address does appear to be valid, and it claims to be an address in `Iran`. There is a city named `Isfahan` in central Iran instead of `Esfahan`, I would guess it is a typo. ![Isfahan - Wikipedia](images/isfahan.jpeg). `get-pack.ir` looks like a legit SEO service company. 


The `a0sa.org` domain is protected by privacy guard and we could not obtain much information about it.

The server returned a 302 response when I performed a quick curl on the URL. 

```
└─$ curl http://ujam3vxb.a0sa.org/?ty007 -v                                                                                                                                         
*   Trying 13.89.204.84:80...
* Connected to ujam3vxb.a0sa.org (13.89.204.84) port 80 (#0)
> GET /?ty007 HTTP/1.1
> Host: ujam3vxb.a0sa.org
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Mon, 31 May 2021 02:16:00 GMT
< Server: Apache
< Location: https://bing.com
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host ujam3vxb.a0sa.org left intact
                                                           
```

The server will redirect the browser to `https://bing.com`. It looks like the server has some detection mechanisms to prevent their second stage payload being sent to everyone.

Using my limited security knowledge, I would guess the checking is based on one or more of the following:

* Time of the day, the adversary might be working in a different time-zone or their targeted users are in a specific timezone.
* User-Agent, which tells the attacker what browser and what operating system the victim is using.
* IP Address / Geolocation, the email is written in traditional chinese, it is likely that the attacker is targeting Hong Kong / Taiwan users. 

## Testing 

#### Enumerating the user-agent using Curl 
There is a delay when we send a request to the server. We will need to wait around 15 seconds to get a response. The website is running on Azure and it probably has some kind of rate limiting. I am getting no reply after sending ~25 requests in a short amount of time. 

```
└─$ curl http://ujam3vxb.a0sa.org/?ty007 -v
*   Trying 13.89.204.84:80...
* Connected to ujam3vxb.a0sa.org (13.89.204.84) port 80 (#0)
> GET /?ty007 HTTP/1.1
> Host: ujam3vxb.a0sa.org
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Empty reply from server
* Connection #0 to host ujam3vxb.a0sa.org left intact
curl: (52) Empty reply from server
```

```
#!/usr/bin/bash

malware_server="http://ujam3vxb.a0sa.org/?ty007"
user_agents="user-agents.txt"

echo "Loading user agents from $user_agents"
i=1
while read line
do
        curl -s -A "$line" -i  $malware_server >> result &
        pids[$i]=$!
        pidss[0]=1
        i=$((i+1))
        sleep 2 # Rate-limiting from Azure. 
done < <(cat $user_agents)

echo "Start waiting for jobs"
i=1
for pid in ${pids[*]}; do
        wait $pid
        echo "Job $pid completed.[$i]"
        i=$((i+1))
done

```

#### Sending the requests from a different IP location using VPN
Tried using Hong Kong / Taiwan VPN, still getting 302 to `bing.com`.

#### Keep a script running that will be triggered every hour to ensure we can catch the server active time

0 * * * * /home/kali/Desktop/try.sh

## Result 

I believe this is a phishing email that pretends to be from "Crypto.com", a legit Hong Kong Crypto trading company. Unable to discover to second stage payload. Will update this post again after getting some output from our cron job. 
