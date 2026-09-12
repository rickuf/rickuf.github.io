---
layout: post
title: "Attacking & Defending Modern Infrastructure Part #2: Getting Started"
author: "Tobias Wicke"
tags: [kubernetes, security, landing zones, red team, blue team, SOC, Clickhouse]
---

OK, let's get our hands dirty. The goal is to create a vulnerable configuration, attack it, detect the attack and then harden the environment in such a way so that the attack is no longer possible. Additionally, I want to design the detection part in such a way that it _could_ be useful in a real world environment. (At least I imagine that it could. I work as a red teamer, I have never built a scaling cloud-native SOC in my life).

## The Architecture: Landing Zones

As described in the previous blog, a shift from on-prem, (more or less) simple networks is currently happening in many corporations. Since defence-in-depth and zero trust are the new cool kids on the block, these concepts have to somehow be included in this new architecture. The so-called landing zone architecture seems to be this new cool kid. At least [Microsoft](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/?tabs=conceptual%2Chubspoke), [AWS](https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-migration/aws-landing-zone.html) and [Google](https://docs.cloud.google.com/architecture/landing-zones?hl=de) are providing guidance on how to implement it. And to be completely honest, it actually makes a lot of sense. Even tough the diagrams the cloud providers provide are big, scary and seem overly complicated. Especially Microsoft must have held an internal competition on who could come up with the most fucked up diagram for a relatively simple concept. (Even tough I like their implementation the most).

The basic concept is that you put trust boundaries between things that don't need to trust each other. Shocker, I know. What a concept. But if you compare it to the way legacy networks were created, it's actually kind of a novalty. In the old days, you had your Active Directory. Everything was part of this Active Directory. And I mean _everything_. To top it all off, LDAP was used as the underlaying protocol. Which allows you by default to read everything that is contained in this directory. Over the years, the tiering concept was established. You sliced this everything up into three pieces, each with its own administrators and access rules. This was used to prevent attackers from elevating their privileges by simply finding logged in Domain Admins on Application Servers (heavily simplified). The landing zone architecture simply takes this concept and applies it _horizontically_. So to speak, each application gets their own domain.

Let's take a look at an example. Imagine you have two important applications in your company: a CRM and a webshop. They are two completey separate applications supported by two completely separate teams. Each team get's their own Account/Subscription/Project and they can do whatever they want with it. To say it in on-prem AD terms: each are put in their own domain with strict trust boundaries between them. That's cool and all, but we still need an IT team that manages stuff and they need to run their own tooling. You guessed it: they get their own landing zone. The same for security. And so on.

> If this is all new to you, I recommend you take the links from above and a LLM of your choosing to dig deeper. Especially the concepts of platform and application landing zones are going to be relevant in later blog posts, as well as landing zone vending.

## The Lab

OK imagine this: you started a new job as a security engineer, everything is cool so far. You have a young, motivated team. The company you joined doesn't use Active Directory, everything runs in the cloud. The first application team finished coding their product, they deploy it. Everyone is really proud of it. You take a look at the application: turns out they developed a perfect replication of the [Damn Vulnerable Web Application](https://github.com/digininja/DVWA). Well, let's get started.

During this series, we will mainly focusing on running the DVWA on Kubernetes, attacking it in various ways, and detect these attacks. To simulate the "landing zones", the setup will be split into two virtual machines.
> I don't really have a plan where this series is going, for now two VMs are sufficient. I can imagine putting some of the stuff on AWS in the future or use cloud-native tooling instead.

One VM will represent our application landing zone. This runs the DVWA on Kubernetes. Imagine this to be exposed to the internet. The second VM will represent our security landing zone. This is not exposed to the internet and will house all of our security tooling. The logs produced in our application LZ will be stored and analyzed somehwere in the security LZ.

> In a perfect world, we could simply ingest all our logs into one big SIEM (Splunk, Sentinel or even Elastic. I don't judge). The big problem with that is, it doesn't scale. Or at least it only scales if your wallet scales as well. Since this is a bad approach and will get you fired rather quickly, so called data lakes have become the go-to solution. So this is what we're about to build.

Due to the unimaginable high cost of throwing everything at our SIEM, I will try to implement the paradigm **logs stay, verdicts travel**. This means: there is one big data lake that holds all of the logs. Based on these logs, alerts are generated that are then investiagted by querying this data lake. This should be engineered in such a way that it scales nicely.

### Setting Up the Data Lake

For the data lake I am going to use [Clickhouse](https://clickhouse.com/). The setup is actually quite easy: On your security VM simply follow the steps to install it using [docker compose](https://clickhouse.com/docs/clickstack/deployment/docker-compose) (I later could imagine running this on K8s as well, but let's not overcomplicate things).

On a fresh Ubuntu VM, do the following:

- Install docker: `curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh ./get-docker.sh`
- Clone the ClickStack repo: `git clone https://github.com/ClickHouse/ClickStack.git && cd ClickStack` 
- Start it: `docker compose up`