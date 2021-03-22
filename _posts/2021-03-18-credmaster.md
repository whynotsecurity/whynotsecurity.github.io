---
title: "CredMaster"
date: 2021-03-18T00:00:03-05:00
categories:
  - blog
tags:
  - blog
  - knavesec
  - CredMaster
  - password spray
share: false
---

CredMaster: Easy & Anonymous Password Spraying

[github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

- [TLDR](#tldr)
- [Setup](#setup)
- [Background](#background)
- [Throttle Evasion](#throttle-evasion)
- [Staying Anonymous](#staying-anonymous)
- [Plugins](#plugins)
- [Detections](#detections)


## TLDR

This tool was designed during a red team engagement while trying to beat a pesky password spray throttle limitation. It now serves as an example of what an adept attacker can build.

CredMaster provides a method of running anonymous password sprays against endpoints in a simple, easy to use tool. The FireProx tool provides the rotating request IP, while the base of CredMaster spoofs all other identifying information.

Current plugins include:
- Office365
- MSOL (Microsoft Online)
- Okta
- Fortinet VPN
- HTTP Basic/Digest/NTLM methods

![general](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-default.png)


## Setup

For some quick setup and cool features.

To use the tool, you'll have to get an AWS access key and secret access key. A great walkthrough can be found here: https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b. If you're concerned about AWS costs, I've been using it extensively with zero costs associated. I believe the metric is something like a few pennies per million requests.

Now, gather a list of users/passwords, and you're ready to spray. The most simple way to spray can be found in the example command:

```
python3 credmaster.py --plugin <pluginname> -u userfile -p passwordfile -a useragentfile --access_key <key> --secret_access_key <key2>
```

Thats it. All you need. But, just because that's all you need, there's still more you want! A few cool options:

- `-o` File output
- `-d/--delay` Delay between passwords, example: try a password every X minutes
- `--passwordsperdelay` Number of passwords to try per delay cycle, example: try X passwords per Y minutes
- Jitter min & max limits
- `--config` A config file to store AWS data, don't hardcode stuff if not necessary
- `--clean` Remove all APIs from AWS, helpful if things aren't cleaned up properly

I like to set it up to run over a long list of passwords, with a delay set up reset lockout counters, but its whatever works for you.


## Background

Normal password spraying tools do exactly what they're designed to do: make an authentication request in order to test the validity of credentials. Unfortunately, this request is made from your local machine, which leaks the IP address. That IP can be blocked, blacklisted, traced, etc.

The next iteration of the game was to spin up proxies to route your traffic through, which would mask your IP address. This was taken to an automated fashion by Mike Felch ([@ustayready](https://twitter.com/ustayready)) in his [CredKing](https://github.com/ustayready/CredKing) tool, which would dynamically create AWS Lambdas in the cloud to submit requests on your behalf. These Lambdas would maintain the same IP address on each request, but the proxy aspect helped keep your information safe. With enough Lambdas, you could spread your authentication attempts across a high number of IP addresses which could help beat throttle rate-limiting. This tool automatically generated Lambdas, then used pre-designed "plugins" to perform the authentication.

Felch's next password spraying game-changer was the introduction of the [FireProx](https://github.com/ustayready/fireprox) tool. This would spin up AWS APIs as a HTTP pass-though proxy. Any request submitted to the API is made to the endpoint specified, this obscures your local machine from the target system. The API rotates your IP address with every request in order to beat IP-based throttle detections and anonymize your machine.

CredMaster is an amalgamation of the two: the plugin-based CredKing suite used to dynamically create FireProx APIs for spraying. CredMaster also does a few other things on the back end to spoof headers, stay anonymous and beat throttling.


## Throttle Evasion

Now, I certainly can't claim that this will completely evade password spray rate-limiting. What I can claim is that it can provide some of the base throttle evasion to date.

Throttle detection _does_ work on a case-by-case basis, a targets on-prem systems are likely to have less sophisticated rate-limiting capabilities. Larger authentication providers like Microsoft & Okta do a good job of detecting and throtting password spray attempts, which make life more difficult for us!

Microsoft employs the Azure Smart Lockout defense system. If a password spray is detected, it will show every account as "locked" regardless of valid password. This detection system is proprietary, so it makes analysis more difficult. According to DaftHack's MSOLSpray tool, use with FireProx appeared to be able to bypass Smart Lockout during testing. My own testing has shown the same.

Okta appears to be a tougher nut to crack. Their detection system _appears_ to be based off `number of auth attempts / time` or some variation of that. Through use of any tool, I've not yet been able to sufficiently beat Okta's throttle attempts. I will note that a single thread and a relatively high jitter has allowed the spray to last a bit longer, though it does end in throttle after a while. Typically, I spray with a thread and high jitter, filter out the throttled attempts, then try again later with the other accounts to get full coverall.

Further research is necessary for all plugins and methods. Each plugin has a section for "throttle notes" on the Wiki.


## Staying Anonymous

The original FireProx does a great job of doing what it was meant to do: rotating the IP address of every authentication request to mask the operator's IP. The AWS API makes this easy, but your IP address can be leaked through the "X-Forwarded-For" header. This, of course, was taken into account by the creator, but is left up to the spraying tool developer to spoof the headers.

Without using either FireProx or CredMaster, standard password sprays leak some sensitive data. A comparison between two consecutive requests is shown below.

![standard1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/standard-1.png)

![standard2](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/standard-2.png)

As you can see, your IP address is leaked (duh) as well as your browser useragent. I'll note that some tools do provide the ability to spoof useragents.

Using FireProx to rotate our IP addresses takes care of the first problem, but introduces a few other anonymity issues. We can start by creating a FireProx API gateway, and launching a quick spray using a random off-the-shelf password spraying tool.

![fireproxlist](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/fireprox-list.png)

![fireproxcli](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/fireprox-cli.png)

Now lets compare the requests from the gateway.

![fireprox1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/fireprox-1.png)

![fireprox2](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/fireprox-2.png)

We have IP rotation, huzzah! But, not without a catch, there are a few new issues introduced.

- Leaked IP address in X-Forwarded-For header
- Repeated useragent
- API gateway ID leaked in x-amzn-apigateway-id header
- Trace ID leaked in X-Amzn-Trace-Id (unsure what this is)

Like I said before, FireProx does have the ability to spoof the X-Forwarded-For header, but that must be done on a per-tool basis. Same concept for useragents again. The important thing here is the leaked API gateway ID, since this is tied to your FireProx instance and therefore your AWS account.

Lets get rid of those!

![credmastercli](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-cli.png)

Credmaster automatically generates AWS Gateways using a modified FireProx tool, then launches a spray against the input users. Lets dig into the requests.

![credmaster1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-1.png)

![credmaster2](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-2.png)

Now we have it: rotating IP address, randomized X-Forwarded-For IP, randomized useragents, spoofed amazon headers. Anonymity.


## Plugins

Currently, there are 5 plugins: Office365, MSOL, Okta, FortinetVPN and HTTP methods. The Office365, Okta and MSOL modules have been heavily tested and are based off other open source tools. The FortinetVPN and HTTP method modules, however, have not been tested (I don't have test endpoints).

I tried to make future development easy, providing a template and instructions to contribute. More plugins == more fun.


## Detections

Since CredMaster automatically spoofs information, the best way to detect is based off the headers being present in the first place. Anywhere dealing with authentication shouldn't allow authentication attempts from AWS APIs, especially with these headers. A few potential methods of detection are:

* The presence of "X-My-" headers (weak detection, could lead to false positives)
* The presence of "x-amzn-apigateway-id" headers (stronger detection, only API gateways have this header)
* Trend analysis, a significant influx of requests with the identifiers shown above

I will note, I'm not great with detection and mitigation techniques. Hopefully someone can find better methods. If you do find better techniques, let me know and I'd be happy to update this blog, give a shoutout, etc.


Feel free to reach out with any questions, I'm always willing to chat.

\- [@knavesec](https://twitter.com/knavesec)
