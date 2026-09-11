---
layout: post
title: "Attacking & Defending Modern Infrastructure Part #1: Setting the scene"
author: "Tobias Wicke"
tags: [kubernetes, security, landing zones]
---

I guess it is public knowledge that attackers and defenders are stuck in a never-ending cat and mouse game on who has the upper hand. From my personal perspective, the tools for defenders have improved tremendously in the last 3-4 years. It has become incredibly difficult to perform red teams in the way we did it 5 years ago: 

* phish random people in the target company
* look what is reachable from there
* escalate privileges and jump around systems in the AD until you find what you're looking for
* ...
* profit

Obviously, this is an exaggeration, but at its core it still holds true. Active Directory is (or was) the backbone of all red teams I was part of. And Active Directory was the main thing we abused for lateral movement and privilege escalation. It was our feel-good oasis of proven attacks and (almost) a guarantee for a successful project.

But this rather comfortable experience changed over the last years: tools detecting these kinds of attacks improved significantly (hello CrowdStrike), as well as the people using these tools. A simple "lets see were we can go from here" usually gets detected by the Blue Team (of course there are still companies at the beginning of their security-journey and especially many small- or medium sized businesses simply don't have the budgets required to actually _secure_ their networks). The logical consequence was that attackers needed to shift their focus. For me personally, this meant: cloud, more cloud and some more cloud. I want to take you on this journey with me: new attacks, new attack paths, old ways of thinking security and an absolute shitton of logs that need to be analyzed.

## The move from classical on-prem

Many companies I talk to are currently in some form of migration. Classical on-premises (and thus Active Directory) environments are getting replaced by either SaaS solutions or, and this is where things are starting to get interesting, self-hosted on Kubernetes. While it was the norm that everything runs on Windows Servers which are domain-joined, this paradigm is slowly starting to shift. From an attacker's perspective this means that our comfy one-size-fits-all attack chains are slowly (and I mean slowly, AD isn't going anywhere in the next few years) going away. It also means that the crown jewels (or critical functions, to say it in TIBER-speak) are slowly moving from Windows Systems to Linux. The funny thing is, that somehow during this shift the age old saying of "you don't need antivirus on Linux" stayed. This means that a completely new playing field opened up for attackers. Hack like it's still 2017!

This effect is amplified by the increased usage of Cloud resources and PaaS-Offerings. I heard of multiple billion-dollar companies that are migrating to cloud-first strategies. Some even go as far as to turn off all datacenters they operate themselves. Sounds good in theory, but what are the consequences of this? What has been a physical server, with physical hardware connected to it (like switches and routers), now becomes an API-call. This in turn means that everyone with the correct permissions can change the infrastructure by using the same API. What used to be a physical job (putting a cable from one switch into another switch) can now be done from anywhere in the world. How great. (Yes I know about virtualization and that it has been the backbone of many companies for the past ~15 years. The big difference is, that your ESXi is not exposed to the internet by default. At least I hope so 👀).

## Cat, meet mouse

The problem that arises from all this is the following: big companies always lag behind. The state of the current SOC we've been facing in our red teams is the following:

* They have some form of EDR running
* Sometimes they supplement the collected telemetry by something like Sysmon
* Sometimes they have network or firewall logs to supplement the telemetry
* They insert all of this data into the SIEM of their choosing (Splunk, Sentinel, etc.) and pay a shitton of money for it
* They supplement the detections the EDR has by writing custom rules in their SIEM. Often times these rules are direct results of past Red Teams or Pentests.

And this works pretty good, as long as attackers stay on the systems that are part of the log-collection. (And like I said in the previous paragraph, defenders have become _really good_ in this part of detection). 

Now imagine the following attack chain (that might or might not have happened like this 👀):

* An external contractor is phished. This grants access to the company's Git.
* A tool like [Trufflehog](https://github.com/trufflesecurity/trufflehog) is used to search for credentials in Git
* Valid AWS credentials are found
* The credentials have access to a Kubernetes cluster
* Inside the cluster, an application has access to the database
* An attacker creates a Kubeconfig using the AWS API for the cluster
* Using this Kubeconfig, an attacker jumps on the backend pod and connects to the prod-database.
* The attacker dumps the prod database.

How much of this is the SOC able to detect with the logs it currently collects? Hint: next to nothing. No endpoint is touched in this chain, no firewall is passed. This means in turn, all the relevant logs _are stored somewhere else_. Cloud providers as well as Git-services allow to export logs. In AWS these are CloudTrail logs, in Azure the AuditLog is needed. But ingesting all these logs for every prod, staging, dev and test environment would simply blow any budget out of proportion. Remember: SIEMs are really, really expensive.

## Kubernetes is its own beast

To top it all off: Kubernetes is its own ecosystem with its own attack paths and misconfigurations. This means that if your crown jewels are living in Kubernetes in a cloud environment, it's not enough to additionally look for attacks in the Cloud's logs. You need to look at the infrastructure its running on as well. In the old days, this was done automatically by simply enrolling your application servers in the EDR of your choosing. But lets be honest, who does that with a managed Kubernetes cluster? How would that even work when worker nodes can be automatically added and removed by the cloud provider?

## Conclusion

In this series of blog posts, I am going to shed a light on some of these challenges. How do attackers actually attack Kubernetes? How do attackers attack Cloud environments? How can these attacks be detected? How can these attacks be blocked before anything bad happens? How is it possible to scale this in a modern landing zone architecture?

I plan on showing how I changed the way I think about red teams, and how I experiment with different technologies to rethink the way detection might work in the future.