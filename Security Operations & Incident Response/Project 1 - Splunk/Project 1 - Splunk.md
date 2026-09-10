# Project 1 - Splunk

# Boss of SOC v3 Fall 26 - CTF Walkthrough

This project involves an incident investigation of the **Frothly** brewery environment using Splunk against the `botsv3` (Boss of the SOC v3) dataset. The investigation traces an AWS console compromise, a publicly exposed S3 bucket, a cryptomining malware infection (JSCoinMiner), and a leaked AWS access key - using SPL searches to pull the relevant evidence out of the logs.

---

### 1. Who attempted to log in to the Frothly AWS account console?

```
index="botsv3" earliest=0 sourcetype=aws* "console" eventName=ConsoleLogin | stats count by userIdentity.userName
```

Console login search results

![Console login search results](images/image1.png)

Console login search results

**Explanation:**
Since the question mentions “AWS”, I began by searching if there was any sourcetype(s) for AWS using `index="botsv3" earliest=0 | stats count by sourcetype`, and there were three for AWS. Therefore, `aws*` just selects all three. Pairing this with `console` narrows the results to a field named `eventName`. Filtering on `ConsoleLogin` and grouping by the `userIdentity.userName` field returned only one user.

---

### 2. Which AWS region did that user make the most API calls to?

```
index="botsv3" earliest=0 sourcetype=aws* "userIdentity.userName"=bstoll | stats count by awsRegion | sort - count
```

API calls by region

![API calls by region](images/image2.png)

API calls by region

**Explanation:**
Since we already knew from the previous question that the user was `bstoll`, this one was just a matter of filtering AWS events down to that username and grouping by `awsRegion`. Sorting descending by count puts the busiest region at the top of the list.

---

### 3. What is the size of the CPU cache of the server `gacrux.i-09cbc261e84259b54`?

**Answer requirement:** 5-digit number

```
index="botsv3" earliest=0 sourcetype=* host="gacrux.i-09cbc261e84259b54" | stats count by sourcetype
```

Sourcetypes for the host

![Sourcetypes for the host](images/image3.png)

Sourcetypes for the host

```
index="botsv3" earliest=0 sourcetype=hardware host="gacrux.i-09cbc261e84259b54"
```

Hardware inventory event

![Hardware inventory event](images/image4.png)

Hardware inventory event

**Explanation:**
Rather than guess the sourcetype, I first listed every sourcetype that exists for that specific host. Among a long list of Unix and application logs sat one called `hardware`, which stood out as the obvious candidate for CPU/memory inventory data. Re-running the search scoped to `sourcetype=hardware` for that host returns a single event with a `KEY`/`VALUE` layout — `CPU_TYPE`, `CPU_COUNT`, `MEMORY_REAL`, and the one we want, `CPU_CACHE` .

---

### 4. What is the event ID of the API call that made the S3 bucket publicly accessible?

```
index="botsv3" earliest=0 sourcetype=aws* bstoll Put
```

PUT event from bstoll

![PUT event from bstoll](images/image5.png)

PUT event from bstoll

**Explanation:**
Knowing bstoll was the user in question, filtering AWS events down to that user plus the `Put` action surfaces the ACL-modifying calls on the bucket. Two `REST.PUT.ACL` events show up: one at 1:01:46 PM and another at 1:57:54 PM. Since the bucket had to be made public before it could be exploited, the earlier one - 1:01:46 PM - is the call that granted public access. The later call at 1:57:54 PM most likely reverted the bucket back to private.

---

### 5. What is the name of the S3 bucket that was made publicly accessible?

```
index="botsv3" earliest=0 sourcetype=aws* bstoll Put
```

S3 bucket name

![S3 bucket name](images/image6.png)

S3 bucket name

**Explanation:**
That same `PUT.ACL` event from the previous question names the bucket right in the request path (`.../frothlywebcode?acl=`), so no extra searching was needed.

---

### 6. What text file was successfully uploaded to the bucket while it was public?

```
index="botsv3" earliest=0 "frothlywebcode" *.txt sourcetype="aws:s3:accesslogs"
```

Uploaded text file

![Uploaded text file](images/image7.png)

Uploaded text file

**Explanation:**
With the bucket name confirmed, I searched the `aws:s3:accesslogs` sourcetype for that bucket’s identifier together with any `*.txt` request, since the question specifically asked for a text file.

---

### 7. What IP address uploaded the `.tar.gz` file into the bucket while it was public?

```
index="botsv3" earliest=0 "frothlywebcode" "*.tar.gz" PUT 200
```

Upload of tar.gz file

![Upload of tar.gz file](images/image8.png)

Upload of tar.gz file

**Explanation:**
Two results came back, both with a `PUT` command. I distinguished between them by looking at the time field. The S3 bucket was made public at 1:04 PM and possibly private again at 1:57 PM, so anything uploaded to the bucket had to fall between 1:05–1:56 PM - which automatically ruled out the result highlighted in red.

---

### 8. What website hosted the JSCoinMiner malware blocked by Symantec Endpoint Security?

**Answer guidance:** the part between `www.` and `.com` (e.g. `google` for `www.google.com`)

```
index="botsv3" earliest=0 "JSCoinMiner" "www." ".com"
```

JSCoinMiner detection

![JSCoinMiner detection](images/image9.png)

JSCoinMiner detection

**Explanation:**
Since the answer had to be a domain name, I searched for `JSCoinMiner` together with the literal strings `www.` and `.com` to filter straight to events that actually contain a URL. That matches a Symantec Endpoint Protection block event whose `Intrusion URL` field reads `www.brewertalk.com.`

---

### 9. According to Symantec/Broadcom, what is the severity of this coin miner threat?

[https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=31204](https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=31204)

Broadcom attack signature severity

![Broadcom attack signature severity](images/image10.png)

Broadcom attack signature severity

**Explanation:**
The block event from the previous question already names the exact signature that fired. Looking that signature up directly on Broadcom’s Attack Signatures database (Symantec’s parent company) shows its severity listed as **Medium.**

---

### 10. How many hosts performed DNS queries for `coinhive.com`?

**Answer guidance:** answer should be a number

```
index="botsv3" earliest=0 "coinhive.com" | stats count by host | dedup host
```

Hosts querying coinhive.com

![Hosts querying coinhive.com](images/image11.png)

Hosts querying coinhive.com

**Explanation:**
The `dedup host` gives three distinct hosts: `BSTOLL-L`, `MKRAEUS-L`, and `splunkhwf.froth.ly`. That last one is the firewall that every query passes through on its way out, so it isn’t really a “host that performed a DNS query” in the sense the question means - it just relays everyone else’s traffic. Excluding it leaves **2** genuine hosts.

---

### 11. According to VirusTotal, is `coinhive.com` malicious?

**Answer guidance:** Yes or No

VirusTotal lookup for coinhive.com

![VirusTotal lookup for coinhive.com](images/image12.png)

VirusTotal lookup for coinhive.com

**Explanation:**
VirusTotal’s community score shows 12 out of 89 security vendors flagging `coinhive.com` as malicious. That’s a minority, but more than enough vendors including Kaspersky, though not Bitdefender.

---

### 12. What is the short hostname of the only Frothly endpoint that defeated the cryptocurrency threat?

**Answer guidance:** e.g. `ahamilton` instead of `ahamilton.mycompany.com`

```
index="botsv3" earliest=0 "JSCoinMiner" ("blocked" OR "quarantined" OR "cleaned" OR "deleted") | stats count by host | dedup host
```

![Hosts with cleaned/blocked events](images/image13.png)

![Host counts](images/image14.png)

**Explanation:**
Only two hosts show up at all: `BTUN-L` with 54 matching events and `SEPM` with 46. `SEPM` is Symantec Endpoint Protection Manager itself - the management server, not an actual user endpoint -  so it doesn’t count as a Frothly workstation that fought off the malware. 

---

### 13. Which user sent the most messages, according to the mail logs?

**Answer guidance:** full email address (e.g. `bob@nalc.com`)

```
index="botsv3" earliest=0 sourcetype="ms:o365:reporting:messagetrace" | stats count by SenderAddress | sort - count
```

![Message trace by sender](images/image15.png)

![Sender counts](images/image16.png)

**Explanation:**
The `ms:o365:reporting:messagetrace` sourcetype already normalizes each message’s sender into a `SenderAddress` field, so grouping by that field and sorting by count by descending order did the rest. 

---

### 14. What support case ID did Amazon open after a Frothly employee leaked AWS keys to an external repo?

```
index="botsv3" earliest=0 "case ID"
```

AWS support case notification

![AWS support case notification](images/image17.png)

AWS support case notification

**Explanation:**
AWS’s automated compromise notifications always reference a support “case ID” by name, so searching for that literal phrase was enough to isolate the one relevant email. Its `subject` field reads “Amazon Web Services: New Support case: XXXXXX”

---

### 15. What AWS access key ID was compromised?

AWS access keys consist of two parts: an access key ID (e.g. `AKIAIOSFODNN7EXAMPLE`) and a secret access key (e.g. `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`).

```
index="botsv3" earliest=0 "access key"
```

Access key ID event

![Access key ID event](images/image18.png)

Access key ID event

**Explanation:**
Only one result showed up with this filter - the same AWS compromise-notification email from question 14. Expanding its `content` field showed the full notice.

---

### 16. What was the secret access key leaked to the external repository?

```
index="botsv3" earliest=0 "access key"
```

Secret access key event

![Secret access key event](images/image19.png)

Secret access key event

**Explanation:**
The same compromise email from questions 14 and 15 links directly to the exposed file on GitHub. Following that link to
[https://github.com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak](https://github.com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak)

Leaked credentials file on GitHub

![Leaked credentials file on GitHub](images/image20.png)

Leaked credentials file on GitHub

---

### 17. Using the leaked key, what full user agent string did the adversary use to attempt to describe an account?

```
index="botsv3" earliest=0 "AKIAJOGCDXJ5NW5PXUPA"
```

Events for the compromised access key

![Events for the compromised access key](images/image21.png)

Events for the compromised access key

**Explanation:**
Searching on the leaked access key ID alone returns 15 events across 9 distinct `eventName` values (`ListAccessKeys`, `CreateUser`, `GetSessionToken`, and so on) - the adversary’s full reconnaissance trail. Since the question specifically asks about an attempt to “describe” an account, I filtered down to the `DescribeAccountAttributes` event.

```
index="botsv3" earliest=0 "AKIAJOGCDXJ5NW5PXUPA" eventName=DescribeAccountAttributes | stats count by userAgent
```

User agent for DescribeAccountAttributes call

![User agent for DescribeAccountAttributes call](images/image22.png)

User agent for DescribeAccountAttributes call

That single event’s `userAgent` field reads xxxxxx - an unusual, non-standard client rather than the AWS CLI or SDK seen in Frothly’s own admin activity, which is what marks this call as the adversary’s.