# nmap-scan

Other similar libraries wrap Nmap commands in Python functions. The rationale for this approach is that the Nmap scanner is very complex, and the wrapper functions are simpler. This is a misconception.

The Nmap scanner is usually used by professionals (network engineers) who know not only its commands, but also how it works.
When replacing Nmap commands with Python functions, you lose the understanding of how these functions work, how they scan, and so on.
In addition, you need to remember not only the Nmap commands, but also the Python functions that these Nmap commands replace. Why remember Nmap functions and some library functions?

The nmap-scan library does not wrap each Nmap command in a Python function. You use it as if you were using a simple Nmap scanner. By passing raw Nmap commands to the scan function. The scanner outputs the following formats: JSON, dict, list dataclass.

For example, if you want to scan top 10 ports. Nmap scanner:

```sh
$ nmap 10.10.10.1 --top-ports 10
```
Using the nmap-scan library:
```python
import nmap_scan
nmap = nmap_scan.Nmap()
results = nmap.scan(['10.10.10.1'], '--top-ports 10')
# Get the result in JSON format
results.get_scan_result_as_json()
# Get the result as a list of dataclass
results.get_scan_result_as_dataclasses()
# Get the result as dict
results.get_raw_nmap_output_as_dict()
```

Ping scanning. Nmap scanner:

```sh
nmap -n -sn -PE --min-rtt-timeout 1s 10.10.1.64-128 10.10.2.100
```
Using the nmap-scan library:
```python
import nmap_scan
nmap = nmap_scan.Nmap()
results = nmap.scan(['10.10.1.64-128', '10.10.2.100'],
					'-n -sn -PE --min-rtt-timeout 1s')
```

#### Installing nmap-scan

```sh
$ git clone https://github.com/mgorbatenko23/nmap-scan.git
$ pip install -r requirements.txt
$ pip install ./nmap-scan-main

$ apt-get install nmap
```
