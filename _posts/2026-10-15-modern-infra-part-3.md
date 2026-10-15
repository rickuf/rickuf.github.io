---
layout: post
title: "Attacking & Defending Modern Infrastructure Part #3: Extending the logs"
author: "Tobias Wicke"
tags: [kubernetes, security, landing zones, red team, blue team, SOC, Clickhouse]
---

In the previous blog I started with the general setup of the infrastructure: two simulated landing zones. One containing the security infrastructure (in this case it is "just" ClickHouse). The other contains our application layer: a k3s cluster running Damn Vulnerable Web Application.

At the moment, all Cilium events events are forwarded to ClickHouse. This means we have all the firewall logs from inside our cluster. Good start, but not enough to really get into the details of disigning custom detections. This blog has two goals:

1. Extending the collected logs with Tetragon to gain visibility into containers
2. Fine tune the current log sources to decrease the overall noise level

Let's get started.

## Adding Tetragon

OK, what exactly is Tetragon? [Tetragon](https://tetragon.io/) uses eBPF under the hood to inspect what the containers running on a host are doing (maybe I'll write a complete blogpost explaining how everything worls together one day). This telemetry is then exported to logfile, just the same as Cilium. What a coincidence - they are both made by the same people based on the same stack.

With this, we have visibility into what is happening inside a container, as well as what the container tries to reach. With this, we'll have everything we need to really detect attacks.

## Reducing Noise