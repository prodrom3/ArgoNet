# ArgoNet

ArgoNet is a robust networking tool inspired by the legendary ship Argo from Greek mythology, which explores the digital seas to retrieve valuable information like the Argonauts in search of the Golden Fleece. ArgoNet combines geolocation, domain resolution, and network path analysis (traceroute) to provide comprehensive insights into network entities.

<p align="center">
  <img width="460" height="460" src="https://github.com/prodrom3/ArgoNet/assets/7604466/6343df52-d5e6-4c1c-b1cf-3e904b694331">
</p>

## Features
- **Geolocation**: Determines the city and country associated with an IP address using the GeoLite2 City database.
- **Domain IP Resolution**: Resolves domain names into their corresponding IP addresses.
- **Network Path Analysis (Traceroute)**: Visualizes the path network packets take to a specified IP address, helping identify the route and potential bottlenecks.

## Installation

### Prerequisites
You will need Python 3.x installed on your machine, and administrative privileges may be required for certain network operations like traceroute.

### Required Libraries
Install the necessary Python libraries using pip:
```bash
pip install geoip2 scapy
```
### GeoLite2 City Database
Download the GeoLite2 City database from MaxMind (you will need to create a free account) and place the .mmdb file in a known directory on your filesystem.

## Usage

### Command Line Interface
To run ArgoNet from the command line, simply pass an IP address or domain name as an argument:

```bash
python argonet.py [IP_ADDRESS_OR_DOMAIN]
```
### Examples
1. IP Address Lookup
```bash
python argonet.py 192.168.1.1
```

**Output:**
```bash
The IP address 192.168.1.1 is located in City Name, Country Name
```
2. Domain Name Resolution and Traceroute
```bash
python argonet.py www.example.com
```

**Output:**
```bash
Resolved IPs for www.example.com: ['93.184.216.34', '93.184.216.101']
The first IP address 93.184.216.34 is located in City Name, Country Name
Tracing route to 93.184.216.34:
[Traceroute results]
```

## Contributing
Contributions to ArgoNet are welcome! Please feel free to fork the repository, make improvements, and submit pull requests.

## License
This project is licensed under the MIT License - see the LICENSE.md file for details.

## Support
If you encounter any problems or have suggestions, please open an issue on the GitHub repository.
