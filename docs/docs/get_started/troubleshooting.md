---
description: Common issues
---

# Troubleshooting

Commit-Boost is currently in alpha development so it's likely there are bugs, if you find any or have any question, please reach out on [Twitter](https://x.com/Commit_Boost) or [Telegram](https://t.me/+Pcs9bykxK3BiMzk5).


If you started the modules correctly you should see the following logs.

## PBS
After the module started correctly you should see:
```bash
2024-09-16T19:27:16.004643Z  INFO Starting PBS service address=0.0.0.0:18550 events_subs=0
```

To check that the setup is correct and you are connected to relays, you can trigger manually the `/status` endpoint, by running:

```bash
curl http://0.0.0.0:18550/eth/v1/builder/status -vvv

*   Trying 0.0.0.0:18550...
* Connected to 0.0.0.0 (127.0.0.1) port 18550 (#0)
> GET /eth/v1/builder/status HTTP/1.1
> Host: 0.0.0.0:18550
> User-Agent: curl/7.81.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 0
< date: Mon, 16 Sep 2024 19:32:07 GMT
<
* Connection #0 to host 0.0.0.0 left intact
```

if now you check the logs, you should see:

```bash
2024-09-16T19:32:07.634966Z  INFO status{req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3}: ua="curl/7.81.0" relay_check=true
2024-09-16T19:32:07.642992Z  INFO status{req_id=62f1c0db-f277-49fa-91e7-a9a1c2b2a6d3}: relay check successful
```

If the sidecar is setup correctly, it will receive and process calls from the CL:
#### Register validator
This should happen periodically, depending on your validator setup.

```bash
2024-09-16T19:28:37.976534Z  INFO register_validators{req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0}: ua="Lighthouse/v5.2.1-9e12c21" num_registrations=500
2024-09-16T19:28:38.819591Z  INFO register_validators{req_id=296f662f-0e7a-4f15-be75-55b8ca19ffc0}: register validator successful
```

#### Get header
This will only happen if some of your validators have a proposal slot coming up.

```bash
2024-09-16T19:30:24.135376Z  INFO get_header{req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=2551052}: ua="Lighthouse/v5.2.1-9e12c21" parent_hash=0x641c99d6e4f14bf6d268eb2a8c0dc51c7030ab24e384c0e679f2a6b438d298ea validator_pubkey=0x84fc20b09496341f24abfcb6f407e916ecc317497c5b1bba4970e50e96cf5e731b88e51753064c30cb221453bd71aebf ms_into_slot=135
2024-09-16T19:30:25.089477Z  INFO get_header{req_id=74126c5f-69e6-4961-86a6-6c2597bf15f5 slot=2551052}: received header block_hash=0x0139686e8d251f010153875270256fce6f298d7b3f3f9129179fb86297dffad3 value_eth="0.001399518501462470"
```

#### Submit block
This will only happen if you received a header in the previous call, and if the header is higher than the locally built block.

```bash
2024-09-16T14:38:01.409075Z  INFO submit_blinded_block{req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=2549590}: ua="Lighthouse/v5.2.1-9e12c21" slot_uuid=16186e06-0cd0-47bc-9758-daa1b66eff5c ms_into_slot=1409 block_hash=0xfa135ae6f2bfb32b0a47368f93d69e0a2b3f8b855d917ec61d78e78779edaae6
2024-09-16T14:38:02.910974Z  INFO submit_blinded_block{req_id=6eb9a04d-6f79-4295-823f-c054582b3599 slot=2549590}: received unblinded block
```