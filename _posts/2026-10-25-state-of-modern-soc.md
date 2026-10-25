---
layout: post
title: "The Cloud-Native SOC: How to actually defend against attacks in 2026"
author: tobias_wicke
tags: [blue team, SOC, Security Engineering]
---

As a Red Teamer, I really like to read CrowdStrike's yearly [threat report](https://www.crowdstrike.com/en-us/global-threat-report/). It gives a great overview of what is currently happening and more importantly _which overall trends are emerging_. If you blend out all the marketing and AI-is-killing-us-all-now-give-us-your-money-speek, the picture that is painted is actually quite useful and should be analyzed further:

The typical malware-on-an-endpoint-chain is no longer the primary attack vector. The following statements by CrowdStrike supplement this thesis:

- "82% of detections in 2025 were malware free"
- "37% rise in cloud-conscious intrusions, with 266% increase by state-nexus threat actors"

To top it off, attacks are getting faster (also thanks to AI): "Average eCrime breakout time dropped to 29 minutes [...]".
The last sentence is the actual interesting part. _On average_, attackers need 29 minutes to go from Initial Access to acess to high-value targets. Try finding a SOC that can react in half an hour to a critical alert. I know customers that have contracts with managed SOCs that have reaction times of 24 hours for medium alerts.

As if this wasn't bad enough, CrowdStrike highlights that attackers aim for coverage gaps in the way current detection is thought of. To quote:

> Modern enterprise networks are inherently complex, containing edge devices, identity solutions, endpoints, cloud environments, and virtualization infrastructure. [...]
> Intrusions that span multiple surfaces pose significant detection and response challenges, as many organizations lack comprehensive visibility across all surfaces. Even when organizations monitor each surface individually, the responsibility for triaging alerts impacting each technology is often distributed across different teams with varying levels of expertise, which can lead to fragmented responses and missed threats.

Let me sumarize in my own words: You are only thinking about the endpoint, attackers think about all the other stuff. If you only think about the endpoint, you're fucked.

On a more serious note: this actually is the core problem I see everywhere. Take your tipical billion-dolar corporation. They are invested in security, have a dedicated in-house SOC and have performed 4-5 Red Team engagements over the last 10 years. What has probably been the main focus of these past Red Teams? Malware-Phishing with the goal of somehow gaining high enough privileges in the domain to achieve the predefined goals. As a direct result of this, most SOCs focused on hardening these attack vectors and writing detections for them. Now the 6th Red Team comes along, they try to deploy malware, the SOC does what a SOC does and the Red Team is detected. Everybody's happy and management says they're secure.
But if you start to think about _where the actual crown jewels nowadays reside_, this image starts to crumble. More and more companies shift to a cloud-first strategy. Most of the infrastructure is either SaaS, or runs somewhere in the cloud. **The cloud or SaaS logs usually do not end up in the SIEM.**. Yes, the endpoint is still an important part to detect attacks, but it is by far not the only one. The biggest part of modern attacks is simply not looked at by most SOCs.

Imagine the following attack chain:

1. The attacker gains access to a victim's O365 via social engineering.
2. They search the company's Sharepoint for credentials.
3. They find credentials for ServiceNow (great Blogpost by [MDSec](https://www.mdsec.co.uk/2026/08/when-it-snows-it-pours-anatomy-of-a-servicenow-red-team/) why this is bad)
4. Via ServiceNow, they can push custom PowerShell-Scripts to all devices.
5. The script searches for cloud credentials on the infected devices
6. The attackers gain access to the prod database running in AWS using these credentials

With the current setup of a typical SOC, which steps can be detected? 1 and 5. And I highly doubt that 5 will trigger an alert in any endpoint detection. It is a script pushed by an admin tool that does not infect any computer with malware or does any of the steps a SOC is used to look for. But let's be optimistic and say step 5 generates an alert. What are the chances that it is classified as a false-positive? Even if it is seen as a true positive, now the SOC has to find out were the script came from. They have to talk to the ServiceNow team. The ServiceNow team doesn't know how to do incident response. _Maybe_ someone remembers "Oh yeah, we had a script in sharepoint with the admin credentials in it". Now the Sharepoint team has to bee involved. The list continues. This can take weeks, when the average breakout time shrunk to 29 minutes. The crown jewels are long gone before the defenders even realized they were under attack.

## Extending the Log Collection

OK, to get the full picture we need to collect all logs. This includes identity providers (Entra, Okta, Auth0, etc.), SaaS applications (GitHub, ServiceNow, SAP, etc.) and cloud provider logs (AWS Cloud Trail, Azure Audit Logs, etc.), as well as the existing infrastructure (endpoint, EDR). The first instinct might be to throw all these logs in the SIEM as well and be done with it. This way the SOC can simply write new detection rules for the new stuff and everybody is happy.
Well, not really. Just think about what you are currently paying for SIEM. Then think about what you would be paying if you increased the log volume 10 times.
The solution for this increasingly growing number of logs is a Datalake. It is literally designed to store and analyze petabytes of data in the most (cost)-efficient way possible. Go and ask your data scientist.
For this, I really like to highlight the first part of this blog written by [GrowTherapy](https://engineering.growtherapy.com/post/threat-hunt-ai-how-we-built-an-ai-security-analyst-on-aws-for-under-500-month). An overview over data lakes instead of SIEMs can be found [in this blogpost](https://www.detectionatscale.com/p/the-transition-from-monolithic-siems)

At the moment, most infrastructure for SOCs looks like this:

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm.jpg)

Alerts and telemetry generated by the EDR are stored in the SIEM and analyzed there. This costs a literal shitton of money already. Now, add Entra ID to the mix. This also generates _a ton_ of logs. Inserting this raw telemetry is often times financially not feasible. This means, only the alerts are forwarded.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(1).jpg)

This has the obvious disadvantage that everything that is not in an alert gets lost. Add all the other log sources discussed above and the problem gets even bigger. In comes the datalake: The raw telemetry is now forwarded to the cheap storage that is built for handeling these amounts of data, the alerts are still forwarded to one central position.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(2).jpg)

Other SaaS services, that might not be able to generate alerts on their own, also publish their logs to the datalake.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(3).jpg)

Now to the important part: It is not possible to simply buy tools that can detect all types of threats. No vendor on this planet knows what is normal inside a corporate network as good as the company itself. Every company needs to extend the default rules provided by the security tooling to be fully able to detect attacks. Based on the data in the datalake, custom detection rules are written and executed against the datalake periodically. The alerts are written to the same storage the vendor-alerts written to.

![image](/assets/img/modern-soc/Unbenanntes%20Diagramm(4).jpg)

The technical details on how this is implemented depends on each company and is highly individual. Some only use Azure, some use all three hyperscalers. Some have a datalake like snowflake already, some like open source solutions like ClickHouse more. There is no one size fits all solution for this problem. The obvious advantage is (as specified in the aforementioned blog by GrowTherapy) that if you already have a datalake where you store the logs of your services, _this does not increase the cost_. You just take what's already there and extend it.

The overall goal is: logs stay, verdicts travel.

> If you are interested in the technical details, check out my blog series _Attacking and defending modern infrastructure_.

## One Standard to Rule Them All

That's cool and all, but writing detection rules for each and every log source is getting cumbersome really fast. So I've come to you to talk about our lord and savior: [OCSF](https://ocsf.io/). OCSF is a normalized schema for security logs similar to Elastic's ECS. The full schema can be found here: https://schema.ocsf.io/

OCSF structures logs in different categories. E.g. System Activity, Network Activity or IAM. Each category has sub-categories which further describes whats happening. Take for example the IAM Authentication event. It is one general event for all types of authentication event that can occur. It doesn't matter if it is a login in GitHub, Entra, or the local domain using Kerberos. The event always looks the same.

This means, that if the data is normalized in the datalake to OCSF, queries can be reused across all log sources. For normalization, most datalakes provide some form of materialized view. This can be used to map the original logs to a queryable format without losing the original data. ([AWS Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html) actually does the normalization for you before storing the data)

Let's see how powerful this is with two examples: password spraying and portscans. Both are pretty basic attacks, but they can occur anywhere in a company's infrastructure and have critical impact. Password spraying might be performed by an attacker against internet facing services or against an internal system after compromising a host. The same is true for portscanning. It can be the first indicator of an upcoming attack against external facing infrastructure. But it can also happen in an AWS VPC or even inside a Kubernetes cluster. Since all queries are written against OCSF, one query for each attack handles all of these cases at once.

## Detections and AI 

## The need for speed