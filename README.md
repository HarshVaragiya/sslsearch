# SSL Search

Hunt SSL Certificates for interesting keywords on major cloud service providers. 


Details - https://medium.com/@harsh8v/ssl-search-a-tool-to-identify-infrastructure-and-discover-attack-surfaces-449c83269574


### Installation

- Currently the only way to use this tool is to build the binary using golang. 

```bash
go install github.com/HarshVaragiya/sslsearch@latest
```

## Features
- Search Cloud Service Providers IP Ranges / Given IP CIDR for keywords in SSL Certificate Subject / SANs
- Perform Initial fingerprinting (https server header grabbing / JARM fingerprinting)

![_assets/cli.png](_assets/cli.png)

| Cloud Service Provider      | Region String Example | JARM | Server Header |
| --------------------------- | --------------------- | ---- | ------------- |
| Amazon Web Services         | us-east-1             | ✅   | ✅            |
| Cloudflare                  | -                     | ✅   | ✅            |
| Digital Ocean               | NL_NL-NH_Amsterdam    | ✅   | ✅            |
| Google Cloud Platform       | us-west4              | ✅   | ✅            |
| Oracle Cloud Infrastructure | ca-montreal-1         | ✅   | ✅            |
| Raw CIDR / IP Range         | -                     | ✅   | ✅            |


## Potential uses 
1. Identifying Infrastructure / Attack Surface for a given scope.
2. Bug Bounty recon. 
3. Scanning a whole CSP Region & Identifying Servers / Services of interest along with SSL certificate information.  
4. Scanning the whole Internet / Country's CIDRs & Collecting JARM fingerprints / Server Headers along with SSL certificate information.
5. Finding Mail / RDP / Other services belonging to a target that use x509 certificates to secure connections. 


## Future plans (not a roadmap)
1. Export integrations for cassandra cluster, redis, kafka and elasticsearch.
2. QOL - Split codebase into different packages like libexport, libscan for better code quality.
3. Certificate information like issuer, signature, chain etc to also be stored for analysis.
4. CI/CD Setup with binary package available for download.
5. Integration tests with test docker containers maybe. 


## References
Ideated after following the following research projects : 
- https://github.com/jhaddix/awsScrape
- https://github.com/femueller/cloud-ip-ranges 
- https://github.com/hdm/jarm-go 
- https://github.com/salesforce/jarm 
