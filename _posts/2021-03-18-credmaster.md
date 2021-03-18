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

## TLDR

This tool was designed during a red team engagement while trying to beat a pesky password spray throttle limitations. It now serves as an example of what an adept attacker can build.

CredMaster provides a method of running anonymous password sprays against endpoints in a simple, easy to use tool. The FireProx tool provides the rotating request IP, while the base of CredMaster spoofs all other identifying information.

Current plugins include:
- Office365
- MSOL (Microsoft Online)
- Okta
- Fortinet VPN
- HTTP Basic/Digest/NTLM methods

![general](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-default.png)


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


## Detection and Mitigation

Since CredMaster automatically spoofs information, the best way to detect is based off the headers being present in the first place. This tool spoofs the headers in the same way, introducing a "X-My-{Header}" that overwrites the original header. Anywhere dealing with authentication shouldn't allow authentication attempts from AWS APIs, especially with these headers.

I will note, I'm not great with detection and mitigation direction. Hopefully someone can find better methods.


Feel free to reach out with any questions, I'm always willing to chat.

- [@knavesec](https://twitter.com/knavesec)
