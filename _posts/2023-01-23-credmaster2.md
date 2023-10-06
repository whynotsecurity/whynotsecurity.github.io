---
title: "Credmaster2"
date: 2023-01-23T00:00:00-00:01
categories:
  - blog
tags:
  - blog
  - knavesec
  - CredMaster
  - password sprays
  - fireprox
share: false
---

CredMaster 2: Electric Boogaloo

Upgrades, Modules and Feature Additions 

- [TLDR](#tldr)
- [New Plugins](#new-plugins)
  - [Gmail User Enum](#gmail-user-enumeration)
  - [Office365 User Enum](#office365-managed-tenant-user-enumeration)
  - [OWA/EWS](#owaews)
  - [ADFS](#adfs)
  - [Azure Seamless SSO](#azure-seamless-sso)
  - [Azure Vault](#azure-vault)
  - [MSGraph](#msgraph)
- [Config File Updates](#config-file-updates)
- [New Features](#new-features)
  - [Weekday Warrior](#weekday-warrior)
  - [Notification System](#notification-system)
  - [Header Addition](#header-addition)
  - [FireProx Utilities](#fireprox-utility-functions)
  - [Others](#other-stray-additions)
- [Credits](#credits)

Github: [github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

![screenshot1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster2/1.png)


## TLDR

Roughly 2 years ago, I released CredMaster as an all-in-one password spraying suite. 

If you're familiar with CredMaster, feel free to skip down a paragraph. For those unfamiliar, CredMaster launches password sprays using AWS API Gateways to rotate requesting IP addresses on each request. Credmaster is a plugin-based tool used to run anonymous password sprays in order to beat throttle detections by spoofing and changing identifications markers. This was all based on the stellar research by [@ustayready's](https://twitter.com/ustayready) awesome [Fireprox tool](https://github.com/ustayready/fireprox). Feel free to read the original CredMaster blog post with all the juicy details [here](https://whynotsecurity.com/blog/credmaster/).

Over the time after released, I've continued adding features and modules, while fixing bugs as well. I felt like it would be a great time to update those on the progress of those goals and modifications. The new features are listed below:

- [Config File Updates](#config-file-updates)
- [8 New Plugins](#new-plugins)
- [Notification systems](#notification-system)
- [Weekday Warrior Evasion](#weekday-warrior)
- [FireProx Utilities](#fireprox-utility-functions)
- Color Output
- Automatic logging of successful creds & valid users

**Thank you so much to the members of the community who have contributed your time in helping this tool, either by your own research, direct pull request, bug fixes or issue reports. See the [Credits](#Credits) section for the list of contributors. Special thanks to [Andy Gill](https://twitter.com/ZephrFish) who helped re-write and spark anew many of these features**


## New Plugins

A total of 8 new plugins have been added: 2 user enum, 6 spraying. Andy is working on an MFASweep module at the time of writing, to be pushed and merged soon. 


### Gmail User Enumeration

User enumeration technique for Gmail and GSuite users, based on x0rz's research found [here](https://blog.0day.rocks/abusing-gmail-to-get-previously-unlisted-e-mail-addresses-41544b62b2)

Simply takes an input list of users and will return either valid/unknown user, it _will not_ make an authentication request

```
credmaster.py <config args> --plugin gmailenum -u users.txt
```


### Office365 Managed Tenant User Enumeration

User enumeration for Office365 Managed tenants, via the classic redirect in login.microsoftonline.com. Again, no authentication attempts are made against the account. 

This has been tested with 15 threads and the entirety of [statistically-likely-username's](https://github.com/insidetrust/statistically-likely-usernames) [jsmith.txt](https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt) userlist (~50k usernames) without throttling/limiting.

```
credmaster <config args> --plugin o365enum -u users.txt 
```


### OWA/EWS

These are the classic Outlook Web App (OWA) and Exchange Web Services (EWS) on-prem email solution password sprayers. On-prem password sprays really need no advanced throttle evasion, but always great to have the option.

```
credmaster.py <config args> --plugin {owa | ews} --url https://mail.domain.com
```


### ADFS

This is a tool to spray on-prem AD/FS servers for domain-joined accounts. These are typically juicy since there are less throttle controls for password sprays. Contributed by [frycos](https://twitter.com/frycos).

```
credmaster.py <config args> --plugin adfs --url https://adfs.domain.com
```


### Azure Seamless SSO

The AzureSSO module is for brute-forcing Azure AD instances using the "autologon.microsoftazuread-sso.com" URL method. At the time, this method left no evidence of password spraying attack in Office365 logs. This module is also verbose enough to generally provide user enumeration against Managed Office365 tenants. 

```
credmaster.py <config args> --plugin azuresso --domain tenantdomain.com
```


### Azure Vault

The Azure Vault is a similar module to the MSOL and AzureSSO modules, simply with a different endpoint targeted. This again makes for a more evasive spray since logs aren't always consistent. 

```
credmaster.py <config args> --plugin azuresso --domain tenantdomain.com
```

### MSGraph 

This, again, is yet another MS spraying tool. The target domain is the same as the MSOL tool, with a different resource targeted (`graph.microsoft.com` vs `graph.windows.net`). Simply provides a bit more variety to your desired type of spraying. 

```
credmaster.py <config args> --plugin msgraph
```


## Config File Updates

When I initially created this script, there weren't that many options to choose from. Now there are many. The config file, originally meant for FireProx connection details, has now been modified to support all flags of CredMaster for easy re-use. This was mainly out of a desire to keep certain config options static across campaigns. 

Config file CLI to launch a spray with a filled out config file, it's just that easy:

```
credmaster.py --config config.json
```

Any config options specified in this file can be overridden with CLI inputs. In case a static "operator template" would be preferred, but engagement specific details are preffered. The below command would take all inputs from the config file, but manually specify 8 threads. 

```
credmaster.py --config config.json --threads 8
```

Example Config file options

```
{
  "plugin" : null,
  "userfile" : null,
  "passwordfile" : null,
  "userpassfile" : null,
  "useragentfile" : null,

  "outfile" : null,
  "threads" : null,
  "region" : null,
  "jitter" : null,
  "jitter_min" : null,
  "delay" : null,
  "passwordsperdelay" : null,
  "randomize" : false,
  "header" : null,
  "weekday_warrior" : null,
  "color" : false,

  "slack_webhook" : null,
  "pushover_token" : null,
  "pushover_user" : null,
  "discord_webhook" : null,
  "teams_webhook" : null,
  "operator_id" : null,
  "exclude_password" : false,

  "access_key" : null,
  "secret_access_key" : null,
  "session_token" : null,
  "profile_name" : null
}
```


## New Features

Outside of modules, a few additional features have been added for evasion, user experience and general usability. Some brief summaries of the bigger ones are below:

- WeekDay Warrior: SOC evasion by only spraying during business hours and at common login times
- Notification Systems: Notify yourself when you've got a successful password guess
- Header Addition: Add a custom static header to each request for attribution if desired
- FireProx Utilities: General FireProx utility functions for backend management, API creation, cleaning, etc for easier management on error

As always, all of this information is stored in the Wiki as well ;)


### Weekday Warrior

This was a technique designed out of a desire to spray against an active SOC that may detect your spray and issue password resets to those impacted. While spraying against a client I managed to guess a password correctly, but at a time when no one should be logging in (well after business hours). This resulted in the SOC seeing that anomolous login, resetting the password, and being on higher alert than they would have been.

The WeekDay Warrior feature is designed to help with that by doing three key things:

1. Spraying between standard business hours automatically (~7-5)
2. Specifically spraying at times where a user would log in normally (Morning, Lunch, End of Day)
3. Only spray on normal business days (Monday-Friday)

By doing these three things, a successful password guessed is far more likely to go unnoticed by an active security team, which could then be used further by your team.

So how does this work in practice?

If you wanted to spray a company, you'd first need to figure out what timezone they're in and what their UTC offset is. This way, you're not spraying at _your own_ M-F 9-5, it is your client's timezone. This plugin will then attempt one password per userlist at 8:00, another at 12:00, and one last at 16:00 on each business day. The program would then sleep until the next business day and start again. The command below sprays at times 8, 12, 16 in the timezone UTC -6 (US Central Time)

```
credmaster.py <config args> --weekday_warrior -6
```

![screenshot of delay](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster2/2.png)


### Notification System

Since this spraying tool is meant to be started and then left untouched for a long period of time, many people would like to be alerted when they've successfully guessed a password. As of now, there are configurable alert systems for the Pushover API and then Discord/Slack/Teams Webhooks. These settings can be added to the config file, multiple notification systems can be used. 

The notification system will send a notification for spray start/stops and for valid credentials, sample below. The Operator ID will not be included if it isn't configured. If the password should be "sanitized" from the notification, that can be configured with the "exclude_password" input flag. 


![screenshot of slack notification](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster2/3.png)


### Header Addition

CredMaster's creation was inherently designed to eliminate the possibility of attribution of the authentication requests. This is effective, however, it is sometimes beneficial to a client to verify that you were, indeed, the one making those requests.

The `header` flag can add a custom static flag to each of your requests, which can be relayed to your client at the end of an engagement if desired.

```
credmaster.py <config args> --header "X-Force-Red: Was-Here"
```


### FireProx Utility Functions

CredMaster (obviously) uses FireProx API gateways significantly, but it doesn't allow easy access to their management if an error occurs. There are 3 FireProx utility functions that may help the operator maintain a clean house. I typically use these commands if the spray was cancelled before completion and the script didn't clean up the APIs properly. 

* `credmaster.py --api_list` 

This is essentially the same as the `list` command in the original FireProx. This will iterate over all regions and list out any APIs in use with detailed information. 

![screenshot](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster2/4.png)

* `credmaster.py --api_destroy {id}`

This is essentially the same as the `delete` command in the original FireProx. This will delete an API of the specified ID.

![screenshot](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster2/5.png)

* `credmaster.py --clean`

This is slightly different from the original FireProx, it will instead iterate over every region and delete _every_ instance of a FireProx API (will not touch non-fireprox APIs). It will leave any non-fireprox related APIs, but this is irreversible. Best used for if you have lots of APIs created, but don't want to delete them one-by-one. 


### Other Stray Additions

A few other nice, but not ground breaking additions that were made:

- Ability to randomize the input list of users (`-r`)
- Color output for success/failure upon guesses (`--color`)
- Region selection to create APIs in (`--region`)
- Automatic logging of successful guesses and valid users
- Full rewrite for easier future development
- TODO List


## Credits

As said before, thank you to all those who directly or indirectly supported this project. This list of contributors can always be found on the CredMaster Readme page and within the wiki. The following two made multiple contributions, thank you to them. 

- [Andy](https://twitter.com/ZephrFish)
- [Logan](https://infosec.exchange/@TheToddLuci0)


Always feel free to reach out, thanks for taking the time to read.

- [@knavesec](https://twitter.com/knavesec)
