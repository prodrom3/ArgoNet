import sys
import socket
from geoip2 import database
from scapy.all import traceroute

def get_location(ip_address, db_path='path/to/GeoLite2-City.mmdb'):
    """Retrieves the location information of a given IP address using the GeoLite2 database."""
    try:
        with database.Reader(db_path) as reader:
            response = reader.city(ip_address)
            city = response.city.name if response.city.name else "City Not Found"
            country = response.country.name if response.country.name else "Country Not Found"
            return city, country
    except database.errors.AddressNotFoundError:
        return "Location Not Found", "Location Not Found"
    except Exception as e:
        print(f"Error retrieving location data: {e}")
        return None, None

def resolve_domain(domain):
    """Resolves a domain name to IP addresses."""
    try:
        return socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        return []

def perform_traceroute(target):
    """Performs a traceroute to a given IP address."""
    try:
        result, _ = traceroute(target, maxttl=20)
        return result
    except PermissionError:
        return "Traceroute requires administrative privileges."
    except Exception as e:
        return f"Traceroute failed: {e}"

def validate_ip(ip):
    """Checks if the string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "www.google.com"  # default to Google for demonstration
    if validate_ip(target):
        city, country = get_location(target)
        print(f"The IP address {target} is located in {city}, {country}")
    else:
        ips = resolve_domain(target)
        if ips:
            print(f"Resolved IPs for {target}: {ips}")
            # Example output of first IP's location and traceroute
            city, country = get_location(ips[0])
            print(f"The first IP address {ips[0]} is located in {city}, {country}")
            print(f"Tracing route to {ips[0]}:")
            print(perform_traceroute(ips[0]))
        else:
            print(f"No IPs found for {target}")
