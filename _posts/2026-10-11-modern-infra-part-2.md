---
layout: post
title: "Attacking & Defending Modern Infrastructure Part #2: Getting Started"
author: "Tobias Wicke"
tags: [kubernetes, security, landing zones, red team, blue team, SOC, ClickHouse]
---

OK, let's get our hands dirty. The goal is to create a vulnerable configuration, attack it, detect the attack and then harden the environment in such a way that the attack is no longer possible. Additionally, I want to design the detection part in such a way that it _could_ be useful in a real-world environment. (At least I imagine that it could. I work as a red teamer, I have never built a scaling cloud-native SOC in my life).

## The Architecture: Landing Zones

As described in the previous blog, a shift from on-prem, (more or less) simple networks is currently happening in many corporations. Since defence-in-depth and zero trust are the new cool kids on the block, these concepts have to somehow be included in this new architecture. The so-called landing zone architecture seems to be this new cool kid. At least [Microsoft](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/?tabs=conceptual%2Chubspoke), [AWS](https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-migration/aws-landing-zone.html) and [Google](https://docs.cloud.google.com/architecture/landing-zones?hl=de) are providing guidance on how to implement it. And to be completely honest, it actually makes a lot of sense. Even though the diagrams the cloud providers provide are big, scary and seem overly complicated. Especially Microsoft must have held an internal competition on who could come up with the most fucked up diagram for a relatively simple concept. (Even though I like their implementation the most).

The basic concept is that you put trust boundaries between things that don't need to trust each other. Shocker, I know. What a concept. But if you compare it to the way legacy networks were created, it's actually kind of a novelty. In the old days, you had your Active Directory. Everything was part of this Active Directory. And I mean _everything_. To top it all off, LDAP was used as the underlying protocol. Which allows you by default to read everything that is contained in this directory. Over the years, the tiering concept was established. You sliced this everything up into three pieces, each with its own administrators and access rules. This was used to prevent attackers from elevating their privileges by simply finding logged-in Domain Admins on Application Servers (heavily simplified). The landing zone architecture simply takes this concept and applies it _horizontally_. So to speak, each application gets their own domain.

Let's take a look at an example. Imagine you have two important applications in your company: a CRM and a webshop. They are two completely separate applications supported by two completely separate teams. Each team gets their own Account/Subscription/Project and they can do whatever they want with it. To say it in on-prem AD terms: each is put in their own domain with strict trust boundaries between them. That's cool and all, but we still need an IT team that manages stuff and they need to run their own tooling. You guessed it: they get their own landing zone. The same for security. And so on.

> If this is all new to you, I recommend you take the links from above and an LLM of your choosing to dig deeper. Especially the concepts of platform and application landing zones are going to be relevant in later blog posts, as well as landing zone vending.

## The Lab

OK, imagine this: you started a new job as a security engineer, everything is cool so far. You have a young, motivated team. The company you joined doesn't use Active Directory, everything runs in the cloud. The first application team finished coding their product, they deploy it. Everyone is really proud of it. You take a look at the application: turns out they developed a perfect replication of the [Damn Vulnerable Web Application](https://github.com/digininja/DVWA). Well, let's get started.

During this series, we will mainly focus on running the DVWA on Kubernetes, attacking it in various ways, and detecting these attacks. To simulate the "landing zones", the setup will be split into two virtual machines.

> I don't really have a plan where this series is going, for now two VMs are sufficient. I can imagine putting some of the stuff on AWS in the future or using cloud-native tooling instead.

One VM will represent our application landing zone. This runs the DVWA on Kubernetes. Imagine this to be exposed to the internet. The second VM will represent our security landing zone. This is not exposed to the internet and will house all of our security tooling. The logs produced in our application LZ will be stored and analyzed somewhere in the security LZ.

> In a perfect world, we could simply ingest all our logs into one big SIEM (Splunk, Sentinel or even Elastic. I don't judge). The big problem with that is, it doesn't scale. Or at least it only scales if your wallet scales as well. Since this is a bad approach and will get you fired rather quickly, so-called data lakes have become the go-to solution. So this is what we're about to build.

Due to the unimaginably high cost of throwing everything at our SIEM, I will try to implement the paradigm **logs stay, verdicts travel**. This means: there is one big data lake that holds all of the logs. Based on these logs, alerts are generated that are then investigated by querying this data lake. This should be engineered in such a way that it scales nicely.

To do this, I am taking heavy inspiration from this [blog](https://engineering.growtherapy.com/post/threat-hunt-ai-how-we-built-an-ai-security-analyst-on-aws-for-under-500-month) by Grow Therapy. Here, logs are stored inside a data lake. On a schedule, detections are run against this data lake. Alerts are then pushed in a uniform format to somewhere people can react to. At first, I am going to implement it on-prem. In a later part, it is planned to rebuild everything in a cloud-native way and include cloud logs as well.

Let's summarize: SIEMs are fucking expensive. Way too expensive to store everything you need to actually detect and investigate incidents in modern environments. Because of this, logs are stored in a really cheap way and analyzed when they go into this store. This is what we are going to build in this blog.

### Setting Up the Data Lake

For the data lake I am going to use [ClickHouse](https://clickhouse.com/). The setup is actually quite easy: on your security VM, simply follow the steps to install it using [docker compose](https://clickhouse.com/docs/clickstack/deployment/docker-compose) (I later could imagine running this on K8s as well, but let's not overcomplicate things).

On a fresh Ubuntu VM, do the following:

- Install docker: `curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh ./get-docker.sh`
- Clone the ClickStack repo: `git clone https://github.com/ClickHouse/ClickStack.git && cd ClickStack`
- Change the `HYPERDX_APP_URL` variable in the .env file (in my case HYPERDX_APP_URL=<http://192.168.188.110>)
- Uncomment the following lines:

```yaml
  ch-server:
    [...]
    ports:
      - 8123:8123 # http api
```

> Hint: This exposes ClickHouse to the internet if you are running it on an internet-exposed machine. Be _really_ careful when you do this.

- Start it: `docker compose up`

After browsing to `<your_ip>:8080`, you should be able to register.

![image](/assets/img/part2/Bildschirmfoto%202026-09-12%20um%2022.38.23.png)

If everything worked as expected, you should be greeted by a UI after logging in.

![image](/assets/img/part2/Bildschirmfoto%202026-09-12%20um%2022.46.47.png)

### Setting Up K8s

For the Kubernetes part, I will use k3s. Simply because it's easy to set up and "just works". For observability I'll use Cilium, Hubble and Tetragon. Simply because I like eBPF and that's what everyone seems to be using at the moment. To get the logs from K8s to the data lake, I'll use [Vector](https://github.com/kaasops/vector-operator).

Perform the following steps to install everything we need:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --flannel-backend=none \
  --disable-network-policy \
  --disable-kube-proxy \
  --disable=traefik \
  --write-kubeconfig-mode=644" sh -
```

- `export KUBECONFIG=/etc/rancher/k3s/k3s.yaml`

```bash
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
```

- `sudo snap install helm --classic`
- `helm install cilium oci://quay.io/cilium/charts/cilium --version 1.20.1   --namespace kube-system   --set operator.replicas=1   --set kubeProxyReplacement=true   --set k8sServiceHost=$NODE_IP   --set k8sServicePort=6443   --set ipam.operator.clusterPoolIPv4PodCIDRList='{10.42.0.0/16}'   --set hubble.relay.enabled=true   --set hubble.ui.enabled=true`
- `cilium version && kubectl get pods -n kube-system`

```bash
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/main/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
```

- Check everything with: `hubble status -P`

If everything worked as expected, you now should have one VM with k3s with Cilium and Hubble running and one VM with ClickHouse.

Your k3s should look something like this:

```bash
$ kubectl get pods -A
NAMESPACE     NAME                                      READY   STATUS    RESTARTS      AGE
kube-system   cilium-envoy-m22vf                        1/1     Running   1 (18m ago)   39d
kube-system   cilium-operator-7b58fc7865-jwghp          1/1     Running   5 (18m ago)   39d
kube-system   cilium-wgtmx                              1/1     Running   1 (18m ago)   39d
kube-system   coredns-54996dc9b4-plphf                  1/1     Running   1 (18m ago)   39d
kube-system   hubble-relay-666d75c98f-f2ppr             1/1     Running   1 (18m ago)   39d
kube-system   hubble-ui-778c684b94-5vzct                2/2     Running   2 (18m ago)   39d
kube-system   local-path-provisioner-58d557dc48-mdv9s   1/1     Running   1 (18m ago)   39d
kube-system   metrics-server-6dc596dfb8-hm9z4           1/1     Running   1 (18m ago)   39d
```

### Installing DVWA

No need to make a science out of it, I'm simply using a community helm chart.

- `helm repo add web-dvwa https://alppkr.github.io/web-dvwa-new/web-dvwa/`
- `helm install my-web-dvwa web-dvwa/web-dvwa --create-namespace --namespace dvwa`
- Wait a few seconds until everything is deployed
- Port forward to access: `$ kubectl port-forward service/web-dvwa-service --address 0.0.0.0 8080:80 -n dvwa`

> Watch out if you have this running on a VPS. The last command will expose DVWA to the internet if no firewall is configured. You really need to be sure you want to do this.

- Then go to `<your_ip>:8080` and log in with `admin:password`

### Setting Up Logging

OK, first we need to set up _where_ we are going to store the actual logs. For this, we create a ClickHouse table which will store all of our raw logs. Go to `http://<your_ip>:8123/play` and run the following SQL statement:

```sql
CREATE DATABASE IF NOT EXISTS raw_logs;

CREATE TABLE raw_logs.hubble_flows
(
    raw      String CODEC(ZSTD(3)),
    time     DateTime64(9, 'UTC')   MATERIALIZED parseDateTime64BestEffortOrZero(JSONExtractString(raw, 'time'), 9, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toDate(time);
```

This uses the materialized view feature of ClickHouse which I am going to use _a lot_ more in the future. For now, it's only important to know that it extracts values specified from the raw JSON and makes it queryable. Pretty neat if you ask me.

Let's insert a test payload:

```sql
INSERT INTO raw_logs.hubble_flows VALUES ( '{"time":"2026-10-11T17:40:05.12345", "foo":"bar", "bar":"foo"}');
```

Great, let's run a test query and see if everything worked:

```sql
SELECT time, raw FROM raw_logs.hubble_flows;
```

> Hint: If you do SELECT * FROM .. you will only get back the raw column. This is because materialized views are not directly returned by the * operator.

Let's update Cilium to actually log to a file we can pick up from disk: `helm upgrade cilium oci://quay.io/cilium/charts/cilium --reuse-values --set hubble.export.static.enabled=true -n kube-system`. Restart Cilium so it picks up the changes: `kubectl -n kube-system rollout restart ds/cilium`

Now watch as the logs are written to disk: `tail -f /var/run/cilium/hubble/events.log`.

### Forwarding the Logs

I am going to install Vector using its helm chart as well. First, create the following values.yaml:

```yaml
role: Agent

service:
  enabled: false
serviceHeadless:
  enabled: false

extraVolumes:
  - name: hubble-export
    hostPath:
      path: /var/run/cilium/hubble
      type: DirectoryOrCreate
extraVolumeMounts:
  - name: hubble-export
    mountPath: /var/run/cilium/hubble
    readOnly: true
customConfig:
  data_dir: /vector-data-dir
  api: {enabled: false}

  sources:
    hubble:
      type: file
      include: [/var/run/cilium/hubble/events.log]

  transforms:
    hubble_raw:
      type: remap
      inputs: [hubble]
      source: '. = {"raw": .message}'

  sinks:
    ch_hubble:
      type: clickhouse
      inputs: [hubble_raw]
      endpoint: http://<your_ip>:8123
      database: raw_logs
      table: hubble_flows
      #auth: {strategy: basic, user: vector, password: "${CLICKHOUSE_PASSWORD}"}
      batch: {timeout_secs: 5}
```

> I actually used Claude for most of the generation. In a first iteration, Claude wanted to mount the whole /var/run/cilium directory into the vector pod. In the directory, however, there are multiple sockets that can be abused. Here's what Claude had to say when I confronted him:
> Yes, that’s a real problem, and a readOnly: true mount doesn’t fix it. A read-only mount only prevents creating and changing files; connecting to a Unix socket on it works just the same. It’s the same reason a docker.sock mounted :ro still gives full Docker control.
>Some of what’s in /var/run/cilium:
>cilium.sock: the agent’s API. Whoever can talk to it can, among other things, replace or delete network policies, which would take out exactly the protection layer your series builds up.
>hubble.sock: read access to all flows on the node.
>envoy/sockets/: the sockets between the agent and Envoy for L7. Depending on the socket, this could even let someone inject fake L7 events into Hubble.
> But I guess AI is going to take all our jobs and make everything secure by default ¯\\_(ツ)_/¯

Now, let's finally install Vector:

- `helm repo add vector https://helm.vector.dev`
- `helm repo update`
- `helm install vector vector/vector   --namespace vector   --create-namespace   --values values.yaml`

Give it a few seconds and logs should start pouring into ClickHouse. But at the moment, it's a little bit uncool to only have a timestamp and the raw data queryable. Let's extend our table schema to something more meaningful:

```sql
ALTER TABLE raw_logs.hubble_flows
    ADD COLUMN IF NOT EXISTS node     LowCardinality(String) MATERIALIZED JSONExtractString(raw, 'node_name'),
    ADD COLUMN IF NOT EXISTS verdict  LowCardinality(String) MATERIALIZED JSONExtractString(raw, 'flow', 'verdict'),
    ADD COLUMN IF NOT EXISTS src_ns   LowCardinality(String) MATERIALIZED JSONExtractString(raw, 'flow', 'source', 'namespace'),
    ADD COLUMN IF NOT EXISTS src_pod  String                 MATERIALIZED JSONExtractString(raw, 'flow', 'source', 'pod_name'),
    ADD COLUMN IF NOT EXISTS dst_ns   LowCardinality(String) MATERIALIZED JSONExtractString(raw, 'flow', 'destination', 'namespace'),
    ADD COLUMN IF NOT EXISTS dst_pod  String                 MATERIALIZED JSONExtractString(raw, 'flow', 'destination', 'pod_name'),
    ADD COLUMN IF NOT EXISTS src_ip   String                 MATERIALIZED JSONExtractString(raw, 'flow', 'IP', 'source'),
    ADD COLUMN IF NOT EXISTS dst_ip   String                 MATERIALIZED JSONExtractString(raw, 'flow', 'IP', 'destination'),
    ADD COLUMN IF NOT EXISTS dst_port UInt16                 MATERIALIZED greatest(
        JSONExtractUInt(raw, 'flow', 'l4', 'TCP', 'destination_port'),
        JSONExtractUInt(raw, 'flow', 'l4', 'UDP', 'destination_port'));
```

If we now run `SELECT time,node, src_ns, dst_ns, src_pod, src_ip, dst_pod, dst_ip, dst_port FROM raw_logs.hubble_flows LIMIT 10;` we should get something way more sensible.

Let's go back to our HyperDX UI and add a new source:

![image](/assets/img/part2/Bildschirmfoto%202026-10-11%20um%2021.38.03.png)

Fill it out as follows:

![image](/assets/img/part2/Bildschirmfoto%202026-10-11%20um%2021.41.48.png)

Now, your dashboard should look something like this:

![image](/assets/img/part2/Bildschirmfoto%202026-10-11%20um%2021.43.49.png)

If you're familiar with Kibana, you'll feel right at home.

With the WHERE clause in the HyperDX UI, we can filter the logs, e.g. `WHERE src_ns = 'dvwa'` to only get logs from our DVWA namespace. Cool.

## Summary

Phew, that was longer than expected, but the groundwork is done: We have a vulnerable Kubernetes cluster and logging (at least Hubble) in place. These logs can comfortably be queried using SQL.

In the next part, I will add Tetragon and the Kubernetes logs as well and try to reduce the noise generated in the logs. From there on, the groundwork is done to finally start hacking some shit.
