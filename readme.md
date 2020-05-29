# Sniffer

Sniff tcp/ip packets
Detect among the sniffed packets detect SSL (https) handshake packets.
Print to stdout each detection in the following format: IP_SRC,TCP_SRC,IP_DST,TCP_DST,COUNT(TCP_OPTIONS).

## Installation
```docker 
docker build -t sniffer .
docker run sniffer
```

## Usage

Result set:

192.168.68.104,58584,18.205.93.2,443(https),3
18.205.93.2,443(https),192.168.68.104,58584,3
192.168.68.104,58583,18.205.93.2,443(https),3
18.205.93.2,443(https),192.168.68.104,58583,3
192.168.68.104,58592,99.86.245.186,443(https),3
99.86.245.186,443(https),192.168.68.104,58592,3

## Contributing

## License
[MIT](https://choosealicense.com/licenses/mit/)