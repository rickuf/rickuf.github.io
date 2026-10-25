---
layout: post
title: "The Cloud-Native SOC: How to actually defend against attacks in 2026"
author: tobias_wicke
tags: [blue team, SOC, Security Engineering]
---

> Hint: I touch on a lot of different aspects and techniques throughout this blogpost. I linked the original blogposts I used to get an understanding of the topic. I **highly** recommend reading them as well to get a deeper understanding on each of the covered topics.

> Also: I work as a red Teamer and talk from the perspective and impressions I've gathered over the last years during numerous Red- and Purple Teams. I do not work in a SOC. I think a lot about how to improve SOCs and their detections, but I don't have operational experience working in one.

As a Red Teamer, I really like to read CrowdStrike's yearly [threat report](https://www.crowdstrike.com/en-us/global-threat-report/). It gives a great overview of what is currently happening and more importantly _which overall trends are emerging_. If you blend out all the marketing and AI-is-killing-us-all-now-give-us-your-money-speak, the picture that is painted is actually quite useful and should be analyzed further:

The typical malware-on-an-endpoint-chain is no longer the primary attack vector. The following statements by CrowdStrike supplement this thesis:

- "82% of detections in 2025 were malware free"
- "37% rise in cloud-conscious intrusions, with 266% increase by state-nexus threat actors"

To top it off, attacks are getting faster (also thanks to AI): "Average eCrime breakout time dropped to 29 minutes [...]".
The last sentence is the actual interesting part. _On average_, attackers need 29 minutes to move laterally from their initial foothold to a second system in the network. Try finding a SOC that can react in half an hour to a critical alert. I know customers that have contracts with managed SOCs that have reaction times of 24 hours for medium alerts.

As if this wasn't bad enough, CrowdStrike highlights that attackers aim for coverage gaps in the way current detection is thought of. To quote:

> Modern enterprise networks are inherently complex, containing edge devices, identity solutions, endpoints, cloud environments, and virtualization infrastructure. [...]
> Intrusions that span multiple surfaces pose significant detection and response challenges, as many organizations lack comprehensive visibility across all surfaces. Even when organizations monitor each surface individually, the responsibility for triaging alerts impacting each technology is often distributed across different teams with varying levels of expertise, which can lead to fragmented responses and missed threats.

Let me summarize in my own words: You are only thinking about the endpoint, attackers think about all the other stuff. If you only think about the endpoint, you're fucked.

On a more serious note: this actually is the core problem I see everywhere. Take your typical billion-dollar corporation. They are invested in security, have a dedicated in-house SOC and have performed 4-5 Red Team engagements over the last 10 years. What has probably been the main focus of these past Red Teams? Malware-Phishing with the goal of somehow gaining high enough privileges in the domain to achieve the predefined goals. As a direct result of this, most SOCs focused on hardening these attack vectors and writing detections for them. Now the 6th Red Team comes along, they try to deploy malware, the SOC does what a SOC does and the Red Team is detected. Everybody's happy and management says they're secure.
But if you start to think about _where the actual crown jewels nowadays reside_, this image starts to crumble. More and more companies shift to a cloud-first strategy. Most of the infrastructure is either SaaS, or runs somewhere in the cloud. **The cloud or SaaS logs usually do not end up in the SIEM.** (At least in my experience with European customers) Yes, the endpoint is still an important part to detect attacks, but it is by far not the only one. The biggest part of modern attacks is simply not looked at by most SOCs.

Imagine the following attack chain:

1. The attacker gains access to a victim's O365 via social engineering.
2. They search the company's SharePoint for credentials.
3. They find credentials for ServiceNow (great Blogpost by [MDSec](https://www.mdsec.co.uk/2026/08/when-it-snows-it-pours-anatomy-of-a-servicenow-red-team/) why this is bad)
4. Via ServiceNow, they can push custom PowerShell-Scripts to all devices.
5. The script searches for cloud credentials on the infected devices
6. The attackers gain access to the prod database running in AWS using these credentials

With the current setup of a typical SOC, which steps can be detected? 1 and 5. And I highly doubt that 5 will trigger an alert in any endpoint detection. It is a script pushed by an admin tool that does not infect any computer with malware or does any of the steps a SOC is used to look for. But let's be optimistic and say step 5 generates an alert. What are the chances that it is classified as a false-positive? Even if it is seen as a true positive, now the SOC has to find out where the script came from. They have to talk to the ServiceNow team. The ServiceNow team doesn't know how to do incident response. _Maybe_ someone remembers "Oh yeah, we had a script in SharePoint with the admin credentials in it". Now the SharePoint team has to be involved. The list continues. This can take weeks, when the average breakout time shrunk to 29 minutes. The crown jewels are long gone before the defenders even realized they were under attack.

## Extending the Log Collection

OK, to get the full picture we need to collect all logs. This includes identity providers (Entra, Okta, Auth0, etc.), SaaS applications (GitHub, ServiceNow, SAP, etc.) and cloud provider logs (AWS CloudTrail, Azure Audit Logs, etc.), as well as the existing infrastructure (endpoint, EDR). The first instinct might be to throw all these logs in the SIEM as well and be done with it. This way the SOC can simply write new detection rules for the new stuff and everybody is happy.
Well, not really. Just think about what you are currently paying for SIEM. Then think about what you would be paying if you increased the log volume 10 times.

The solution for this increasingly growing number of logs is a datalake. It is literally designed to store and analyze petabytes of data in the most (cost)-efficient way possible. Go and ask your data scientist.
For this, I really like to highlight the first part of this blog written by [GrowTherapy](https://engineering.growtherapy.com/post/threat-hunt-ai-how-we-built-an-ai-security-analyst-on-aws-for-under-500-month). A more general overview over data lakes instead of SIEMs can be found [in this blogpost](https://www.detectionatscale.com/p/the-transition-from-monolithic-siems)

At the moment, most infrastructure for SOCs looks like this:

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm.jpg)

Alerts and telemetry generated by the EDR are stored in the SIEM and analyzed there. This costs a literal shitton of money already. Now, add Entra ID to the mix. This also generates _a ton_ of logs. Inserting this raw telemetry is often times financially not feasible. This means, only the alerts are forwarded.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(1).jpg)

This has the obvious disadvantage that everything that is not in an alert gets lost. Add all the other log sources discussed above and the problem gets even bigger. In comes the datalake: The raw telemetry is now forwarded to the cheap storage that is built for handling these amounts of data, the alerts are still forwarded to one central position.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(2).jpg)

Other SaaS services, that might not be able to generate alerts on their own, also publish their logs to the datalake.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(3).jpg)

Now to the important part: It is not possible to simply buy tools that can detect all types of threats. No vendor on this planet knows what is normal inside a corporate network as good as the company itself. Every company needs to extend the default rules provided by the security tooling to be fully able to detect attacks. Based on the data in the datalake, custom detection rules are written and executed against the datalake periodically. The alerts are written to the same storage the vendor alerts are written to.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(4).jpg)

The technical details on how this is implemented depends on each company and is highly individual. Some only use Azure, some use all three hyperscalers. Some have a datalake like snowflake already, some like open source solutions like ClickHouse more. There is no one size fits all solution for this problem. The obvious advantage is (as specified in the aforementioned blog by GrowTherapy) that if you already have a datalake where you store the logs of your services, _this does not increase the cost_. You just take what's already there and extend it.

The overall goal is: logs stay, verdicts travel.

> If you are interested in the technical details, check out my blog series [_Attacking and defending modern infrastructure_]({% post_url 2026-09-11-modern-infra-part-1 %}).

### One Standard to Rule Them All

That's cool and all, but writing detection rules for each and every log source is getting cumbersome really fast. So I've come to you to talk about our lord and savior: [OCSF](https://ocsf.io/). OCSF is a normalized schema for security logs similar to Elastic's ECS. The full schema can be found here: https://schema.ocsf.io/

OCSF structures logs in different categories. E.g. System Activity, Network Activity or IAM. Each category has sub-categories which further describes what's happening. Take for example the IAM Authentication event. It is one general event for all types of authentication event that can occur. It doesn't matter if it is a login in GitHub, Entra, or the local domain using Kerberos. The event always looks the same.

This means, that if the data is normalized in the datalake to OCSF, queries can be reused across all log sources. For normalization, most datalakes provide some form of materialized view. This can be used to map the original logs to a queryable format without losing the original data. ([AWS Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html) actually does the normalization for you before storing the data)

Let's see how powerful this is with two examples: password spraying and portscans. Both are pretty basic attacks, but they can occur anywhere in a company's infrastructure and have critical impact. Password spraying might be performed by an attacker against internet facing services or against an internal system after compromising a host. The same is true for portscanning. It can be the first indicator of an upcoming attack against external facing infrastructure. But it can also happen in an AWS VPC or even inside a Kubernetes cluster. Since all queries are written against OCSF, one query for each attack handles all of these cases at once.

## Improving Detection Speed

So far, so good. I've talked about how SOCs can be able to detect attacks ranging multiple domains and different parts of infrastructure. What hasn't been answered is the second problem: the speed at which these attacks are performed. And the boring answer is: automate whatever you can. How original.

However, I want to point out two really interesting approaches to this.

### Automatically Contacting Employees

[Dropbox](https://dropbox.tech/security/meet-securitybot-open-sourcing-automated-security-at-scale) has written a pretty interesting blog about how they approach this. One of the most time consuming parts is actually contacting the employee that triggered an alert and asking them what the hell they were doing. For this, they created a Slack bot that automatically contacts the person that triggered an alert and asks for clarification. This doesn't have to be Slack. Every major communication platform supports bots in one form or another.
The big takeaway here is that the response is logged as well. If the employee triggered an alert by doing something benign, they need to clarify in the chatbot what they were doing. If they can't explain the alert or don't respond in an adequate timeframe, the alert is escalated.

### Letting AI Do the Gruntwork

The second step to automate might arguably be the more important one: letting AI do the triage. Yes, yes, I know: "Just throw an agent at it bro. Trust me." seems to be the solution to every problem at the moment. But let me specify:

[Figma](https://www.figma.com/en-us/blog/how-we-secure-figmas-internal-systems-with-agents/) wrote a blog post about how they use agents to improve detection capabilities and overall speed. I am not going into all of the details (read Figma's blog, it's really worth it). The interesting part here is that Figma built a RAG platform first to have an easy way to look up past incidents. Only afterwards they realised that this is the perfect platform for an agentic workflow.

I am a big fan of the mantra "What can be done deterministically will be done deterministically". An agent should only be used if the number of steps is not known beforehand or the reasoning of the model actually adds value. Otherwise, you use the slowest but at the same time most expensive solution for the problem.

What does this mean exactly for our SOC-agent and where can it actually add value? Let's assume one of the alerts end up in the previously explained alert store. The security-bot picks it up and asks the user if they can explain it. The user says they don't have a clue and the alert is escalated. The next step is usually to gather additional context, enrich the alert and look at historic data or similar alerts. Remember: what can be done deterministically will be done deterministically. That means that all the enrichment that can be done (e.g. looking up an IP address in IOC lists) automatically is done that way. Only _afterwards_, this data is passed on to the agent. The agent only has a limited set of tools at its disposal: looking up Entra logs, looking up EDR logs, looking up the internal knowledgebase, querying the datalake, etc. The important thing is, that the agent only has read access with all these tools. The agent itself cannot change anything and it isn't able to run custom scripts or access a terminal. With the information gathered, the agent creates a first verdict and forwards it to a human.

Based on this verdict, a human decides to close the ticket or to further escalate.

Based on this, false positives can be differentiated from real alerts in machine speed, rather than human speed.

## Summary

To summarize: attackers are evolving, and most SOCs are still defending against the attacks of 2020. Attacks are mostly malware free, they cross identity, SaaS, cloud and endpoint in a single chain, and attackers move laterally from their initial foothold in about half an hour. A SOC that only watches the endpoint and needs weeks to coordinate five teams will not catch that.
Catching it takes two things. The first is visibility: get _all_ the logs into a datalake instead of the SIEM, normalize them to OCSF so one detection covers every log source, and only send the verdicts to a central place. The second is speed: automate everything that can be automated deterministically, let a bot ask the employee before a human analyst has to, and let a read-only agent do the enrichment and the first triage so humans only make the final call.
The bummer: None of this can be bought off the shelf. It has to be built on top of what the company already has, by people who know what normal looks like in their own environment.
