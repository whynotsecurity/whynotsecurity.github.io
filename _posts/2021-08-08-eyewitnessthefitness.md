---
title: "EyeWitnessTheFitness"
date: 2021-08-08T00:00:03-05:00
categories:
  - blog
tags:
  - blog
  - knavesec
  - EyeWitness
  - external recon
  - WitnessTheFitness
share: false
---

EyeWitnessTheFitness

[github.com/knavesec/EyeWitnessTheFitness](https://github.com/knavesec/EyeWitnessTheFitness)


## TLDR

External scan prevention systems make recon and enum difficult, one of the best ways to bypass that is to distribute your operations to different IP addresses. [Fireprox](https://github.com/ustayready/fireprox) (shoutout [@ustayready](https://twitter.com/ustayready)) makes that easy by rotating the IP on every request, but for a tool like Eyewitness, you'd need to generate a new Fireprox API for every url.

Instead of doing that, use this tool to generate a single Fireprox API that encompasses all your needs, then outputs to a file compatible for direct use with Eyewitness. Easy distributed scan prevention bypass for external recon.


## Theory

On a red team engagement recently, we were doing some limited enumeration of client network URLs but after a certain amount of requests with EyeWitness, they would all start timing out and fail to load. When investigating we were able to load pages manually, but any type of scan would get blocked after a set of time. We needed IP rotation, with the functionality of EyeEitness, enter: TheFitness.

I had already used FireProx generation extensively in my CredMaster tool, but I didn't want to generate a unique API for every host I wanted to witness. For 100 hosts generating 100 APIs is just silly and inefficient, so I started to dig into how the API was generated at the template level. On each template, you can specify granular details about what you want your end URI functionality to do. The standard FireProx template just maps anything after the initial `/` to the end website desired for a straight pass-through. Instead of doing that, I aliased the first URI to be the target domain:

```
/www.google.com/ -> https://www.google.com/
/amazon.com/ -> https://amazon.com/
...
```

While I haven't figured out a way to make this truly generic and dynamic, it does provide the ability to create a single API and pass through to multiple hosts. Taking in a list of target hosts, like a standard EyeWitness target file, I could generate a new template that encompassed everything necessary for the enum scan. Thus, EyeWitnessTheFitness was born.

## Usage

Since this method involves using AWS to create APIs, you'll need access keys. Instructions to get those can be found here: [https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b](https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b). I wouldn't be worried about cost, it's something like a few pennies USD for a few million requests.

Once you have your keys, you can either provide them as CLI, or put them in the `aws.config.template` file for easier use. Simply provide a formatted Eyewitness target file (with http/s already appended!), provide an output file, and a region and you're good to go!

![ewtf-run1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/wtf/ewtf-run1.png)

Using it with Eyewitness, it will make requests to each of the endpoints desired.

![eyewitness-run](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/wtf/eyewitness-run.png)

Then you get your output view.

![eyewitness-results1](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/wtf/eyewitness-results1.png)

![eyewitness-results2](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/wtf/eyewitness-results2.png)

Simple scan prevention bypass.

You can also use this to list and delete those APIs. When listing, the original Fireprox tool won't output these options due to a filtering issue, so I've included that functionality here.

![ewtf-run-delete](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/wtf/ewtf-run-delete.png)

Feel free to reach out with any questions, I'm always willing to chat.

- [@knavesec](https://twitter.com/knavesec)
