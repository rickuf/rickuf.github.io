---
layout: post
title: "Attacking & Defending Modern Infrastructure Part #3: Extending the logs"
author: "Tobias Wicke"
tags: [kubernetes, security, landing zones, red team, blue team, SOC, ClickHouse]
---

In the previous blog I started with the general setup of the infrastructure: two simulated landing zones. One contains the security infrastructure (in this case it is "just" ClickHouse). The other contains our application layer: a k3s cluster running Damn Vulnerable Web Application.

At the moment, all Cilium events are forwarded to ClickHouse. This means we have all the firewall logs from inside our cluster. Good start, but not enough to really get into the details of designing custom detections. This blog has two goals:

1. Extending the collected logs with Tetragon to gain visibility into containers
2. Fine tune the current log sources to decrease the overall noise level

Let's get started.

## Adding Tetragon

OK, what exactly is Tetragon? [Tetragon](https://tetragon.io/) uses eBPF under the hood to inspect what the containers running on a host are doing (maybe I'll write a complete blogpost explaining how everything works together one day). This telemetry is then exported to a logfile, just the same as Cilium. What a coincidence - they are both made by the same people based on the same stack.

With this, we have visibility into what is happening inside a container, as well as what the container tries to reach. Now we'll have everything we need to really detect attacks. It is the Sysmon of Kubernetes (or containers in general).

> Yes, I know that Tetragon can also detect network telemetry. The advantage of Hubble is that it also detects the events if an application were to ship with their own TCP stack. Looking at you, nmap 👀

### Setting up Tetragon

We can install Tetragon by using the official helm chart:

- `helm repo add cilium https://helm.cilium.io`
- `helm repo update`
- `helm install tetragon cilium/tetragon -n kube-system`
- Give it a few seconds and check if logs are written with `sudo tail -f /var/run/cilium/tetragon/tetragon.log`

On the ClickHouse SQL-Playground, create the corresponding logs table for our newly generated Tetragon logs:

```sql
CREATE TABLE raw_logs.tetragon_events
(
    raw        String CODEC(ZSTD(3)),
    time       DateTime64(9, 'UTC')   MATERIALIZED parseDateTime64BestEffortOrZero(JSONExtractString(raw, 'time'), 9, 'UTC'),
    node       LowCardinality(String) MATERIALIZED JSONExtractString(raw, 'node_name'),
    -- top-level key is the event type: process_exec, process_exit, process_kprobe, ...
    event_type LowCardinality(String) MATERIALIZED arrayFirst(k -> startsWith(k, 'process_'), JSONExtractKeys(raw)),
    namespace  LowCardinality(String) MATERIALIZED JSONExtractString(raw, event_type, 'process', 'pod', 'namespace'),
    pod        String                 MATERIALIZED JSONExtractString(raw, event_type, 'process', 'pod', 'name'),
    binary     String                 MATERIALIZED JSONExtractString(raw, event_type, 'process', 'binary'),
    exec_id    String                 MATERIALIZED JSONExtractString(raw, event_type, 'process', 'exec_id'),
    arguments  String                 MATERIALIZED JSONExtractString(raw, event_type, 'process', 'arguments')
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (event_type, namespace, time);
```

Now, we only need to ship the generated logs with Vector to ClickHouse, the same way we did it in the previous blog with Hubble. Change the `values.yaml` from the previous blog to now also include the Tetragon logs:

```yaml
[...]
extraVolumes:
  - name: hubble-export
    hostPath:
      path: /var/run/cilium/hubble
      type: DirectoryOrCreate
  - name: tetragon-export 
    hostPath: 
      path: /var/run/cilium/tetragon 
      type: DirectoryOrCreate 
extraVolumeMounts:
  - name: hubble-export
    mountPath: /var/run/cilium/hubble
    readOnly: true
  - name: tetragon-export 
    mountPath: /var/run/cilium/tetragon 
    readOnly: true 
customConfig:
  data_dir: /vector-data-dir
  api: {enabled: false}

  sources:
    hubble:
      type: file
      include: [/var/run/cilium/hubble/events.log]
    tetragon:
      type: file
      include: [/var/run/cilium/tetragon/tetragon.log]

  transforms:
    hubble_raw:
      type: remap
      inputs: [hubble]
      source: '. = {"raw": .message}'
    tetragon_raw:
      type: remap
      inputs: [tetragon]
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
    ch_tetragon:
      type: clickhouse
      inputs: [tetragon_raw]
      endpoint: http://<your_ip>:8123
      database: raw_logs
      table: tetragon_events
      #auth: {strategy: basic, user: vector, password: "${CLICKHOUSE_PASSWORD}"}
      batch: {timeout_secs: 5}
[...]
```

Then apply the new config: `helm upgrade vector vector/vector --reuse-values --namespace vector --values values.yaml`

After waiting for a few seconds, check if logs are arriving in the SQL playground by executing `select * from raw_logs.tetragon_events limit 10;`
> If no logs show up, generate events by abusing the command injection vulnerability in DVWA. It will generate events that are logged by default in Tetragon.

Now, in HyperDX, create a new source which looks like this:

![image](/assets/img/part3/Bildschirmfoto%202026-10-24%20um%2020.09.23.png)

This, in turn, should provide us with a view similar to this:

![image](/assets/img/part3/Bildschirmfoto%202026-10-24%20um%2020.11.04.png)

We now have a live dashboard with every process that is started inside our containers. How cool is that?

### Extending Tetragon to collect file events

Now here comes the kicker: Tetragon is not only able to detect process starts. It can do almost everything that can be collected using eBPF. Let's extend it to also include file accesses in the pods.

Tetragon does this by defining CRDs in the cluster. This means that we can define which events are collected from now on with a simple `kubectl apply`. I'll say it again: how cool is that?

Create a local file with the following content:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-filtered"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "int" # 0x04 is MAY_READ, 0x02 is MAY_WRITE
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:      
      - index: 0
        operator: "Prefix"
        values:
        - "/boot"           # Reads to sensitive directories
        - "/root/.ssh"      # Reads to sensitive files we want to know about
        - "/etc/shadow"
        - "/etc/passwd"
        - "/etc/profile"
        - "/etc/sudoers"
        - "/etc/pam.conf"   # Reads global shell configs bash/csh supported
        - "/etc/bashrc"
        - "/etc/csh.cshrc"
        - "/etc/csh.login"  # Add additional sensitive files here
      - index: 1
        operator: "Equal"
        values:
        - "4" # MAY_READ
    - matchArgs:      
      - index: 0
        operator: "Postfix"
        values:
        - ".bashrc"         # Reads to shell config files bash, csh supported
        - ".bash_profile"   # add any other shell support here.
        - ".bash_login"
        - ".bash_logout"
        - ".cshrc"
        - ".cshdirs"
        - ".profile"        # Reads to common environments files
        - ".login"
        - ".logout"
        - ".history"        # Add additional sensitive files here
      - index: 1
        operator: "Equal"
        values:
        - "4" # MAY_READ
    - matchArgs:      
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"              # Writes to sensitive directories
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/bin"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"          # Writes to logs
        - "/dev/log"
        - "/root/.ssh"        # Writes to sensitive files add here.
      - index: 1
        operator: "Equal"
        values:
        - "2" # MAY_WRITE
  - call: "security_mmap_file"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "uint32" # the prot flags PROT_READ(0x01), PROT_WRITE(0x02), PROT_EXEC(0x04)
    - index: 2
      type: "uint32" # the mmap flags (i.e. MAP_SHARED, ...)
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:      
      - index: 0
        operator: "Prefix"
        values:
        - "/boot"           # Reads to sensitive directories
        - "/root/.ssh"      # Reads to sensitive files we want to know about
        - "/etc/shadow"
        - "/etc/sudoers"
        - "/etc/pam.conf"   # Reads global shell configs bash/csh supported
        - "/etc/profile"
        - "/etc/bashrc"
        - "/etc/csh.cshrc"
        - "/etc/csh.login"
        - ".bashrc"         # Reads to shell config files bash, csh supported
        - ".bash_profile"   # add any other shell support here.
        - ".bash_login"
        - ".bash_logout"
        - ".cshrc"
        - ".cshdirs"
        - ".profile"        # Reads to common environments files
        - ".login"
        - ".logout"
        - ".history"        # Add additional sensitive mmap files here
      - index: 1
        operator: "Equal"
        values:
        - "1" # MAY_READ
      - index: 2
        operator: "Mask"
        values:
        - "1" # MAP_SHARED
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"              # Writes to sensitive directories
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/bin"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"          # Writes to logs
        - "/dev/log"
        - "/root/.ssh"        # Writes to sensitive files add here.
      - index: 1
        operator: "Mask"
        values:
        - "2" # PROT_WRITE
      - index: 2
        operator: "Mask"
        values:
        - "1" # MAP_SHARED
  - call: "security_path_truncate"
    syscall: false
    return: true
    args:
    - index: 0
      type: "path" # (struct path *) used for getting the path
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"              # Truncate to sensitive directories
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"          # Truncate to logs
        - "/dev/log"
        - "/root/.ssh"        # Truncate to sensitive files add here.
```

> This is shamelessly stolen from the Tetragon examples in the official repo under https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring.yaml

This shows how absolutely powerful this whole thing really is. We can specify pre- and suffixes for the files we want to generate events for.

Let's apply it to our cluster:

`kubectl apply -f tetragon/file_access.yaml`.

Then, let's abuse the LFI in our DVWA (http://<dvwa_ip>/vulnerabilities/fi/?page=/etc/passwd) and see what happens:

![image](/assets/img/part3/Bildschirmfoto%202026-10-24%20um%2020.52.51.png)

Well, at least we got an entry. But it's rather ugly and not really informative. Let's update our table to show something more meaningful:

```sql
ALTER TABLE raw_logs.tetragon_events
    ADD COLUMN IF NOT EXISTS function_name LowCardinality(String)
        MATERIALIZED JSONExtractString(raw, event_type, 'function_name') AFTER arguments,
    -- first file_arg / path_arg path in the hook's args
    ADD COLUMN IF NOT EXISTS file_path String
        MATERIALIZED arrayFirst(p -> p != '', arrayMap(a ->
            if(JSONHas(a, 'file_arg'),
               JSONExtractString(a, 'file_arg', 'path'),
               JSONExtractString(a, 'path_arg', 'path')),
            JSONExtractArrayRaw(raw, event_type, 'args'))) AFTER function_name;
```

Then change the data source to include `function_name` and `file_path` by default in the query:

![image](/assets/img/part3/Bildschirmfoto%202026-10-24%20um%2021.07.10.png)

Now we're talking.

> Hint: Currently, failed syscalls are not logged. If you for example try to read /etc/shadow, the call is blocked with an access denied error. The read is denied, so the hook never reports it. I will refine the policies in the future to be more useful.

## Reducing Noise

OK, really nice. Now, if we switch back to the Hubble Flow overview in HyperDX, we see that Hubble generates _way_ more telemetry than our Tetragon events. But if we look at it, most of it is in the `kube-system` namespace. If we dig a bit deeper, most of that is the metrics service.

```bash
$ sudo tail -n 2000 /var/run/cilium/hubble/events.log | jq -r '
  def ep(e): if e.namespace then "\(e.namespace)/\(e.pod_name)"
             else ((e.labels // []) | map(select(startswith("reserved:"))) | join(",")) end;
  "\(ep(.flow.source)) -> \(ep(.flow.destination)):\(.flow.l4.TCP.destination_port // .flow.l4.UDP.destination_port // "-") \(.flow.verdict)"
' | sort | uniq -c | sort -rn | head -20
    407 reserved:host,reserved:kube-apiserver -> kube-system/metrics-server-6dc596dfb8-hm9z4:10250 FORWARDED
    279 reserved:host,reserved:kube-apiserver -> kube-system/coredns-54996dc9b4-plphf:8181 FORWARDED
    131 reserved:host,reserved:kube-apiserver -> kube-system/hubble-relay-5469b6cb6-82sdw:4222 FORWARDED
    109 reserved:host,reserved:kube-apiserver -> kube-system/hubble-ui-59bf9559cc-7vgfl:8081 FORWARDED
     85 reserved:host,reserved:kube-apiserver -> kube-system/tetragon-operator-787f7bdbcc-72v8d:8081 FORWARDED
     62 reserved:host,reserved:kube-apiserver -> kube-system/coredns-54996dc9b4-plphf:8080 FORWARDED
     22  -> :- null
     14 vector/vector-pmx4v -> reserved:world:8123 FORWARDED
     14 reserved:world -> vector/vector-pmx4v:44658 FORWARDED
     14  -> reserved:world:8123 FORWARDED
     11 kube-system/metrics-server-6dc596dfb8-hm9z4 -> reserved:host,reserved:kube-apiserver:34786 FORWARDED
```

Not that ClickHouse can't handle this, but we don't need to waste any precious CPU or RAM on stuff we don't use anyway. Let's create a Hubble denylist config:

First, export the current Cilium config: `helm get values cilium -n kube-system -o yaml > cilium/cilium-values.yaml`

Then change the config so it looks something like this:

```yaml
hubble:
  export:
    static:
      enabled: true
      denyList:
        # kubelet probes and API server calls from the node to system pods
        - '{"source_label":["reserved:host"],"destination_pod":["kube-system/"],"verdict":["FORWARDED"]}'
        # the system pods' replies back to the node
        - '{"source_pod":["kube-system/"],"destination_label":["reserved:host"],"reply":[true],"verdict":["FORWARDED"]}'
```

Then:

- apply the changes: `helm upgrade cilium cilium/cilium -n kube-system -f cilium/cilium-values.yaml`
- restart Cilium: `kubectl -n kube-system rollout restart ds/cilium`

After the restart, the number of ingested logs should decrease drastically:

![image](/assets/img/part3/Bildschirmfoto%202026-10-24%20um%2021.47.36.png)

## Summary

OK nice. In this blog, I added Tetragon to get visibility into what is actually happening inside the container. Additionally, I reduced the overall noise level generated by the Hubble logs to only focus on what is actually useful for us.

In the next part I will finally start doing actual attacks against the cluster. I will show the different types of attacks, how we can detect them using our ClickHouse infrastructure and how to harden the cluster so the attacks become impossible. 