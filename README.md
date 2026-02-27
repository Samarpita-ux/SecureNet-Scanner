# securenet scanner

a python-based command-line network security tool that performs automated network reconnaissance and vulnerability assessment.

## features
- multithreaded port scanning for fast results
- service detection and banner grabbing
- automatic cve lookup via nvd api
- regex-based product and version parsing
- interactive cli mode
- json report export

## how it works
1. takes a target ip or domain
2. scans for open ports using multithreading
3. grabs service banners to identify software versions
4. queries the nvd database for known cves
5. exports results as a json report

## usage
```bash
python netscanner.py
```

## technologies used
- python 3
- socket programming
- nvd api (national vulnerability database)
- threadpoolexecutor for multithreading

## disclaimer
this tool is for educational purposes only. only scan systems you own or have permission to scan. =]
```
