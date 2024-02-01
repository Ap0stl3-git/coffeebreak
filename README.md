# coffeebreak
#
# Bash script to run intitial enumeration and scanning tasks for internal penetration tests.
#
#                     (  )   (   )  )
#                      ) (   )  (  (
#                      ( )  (    ) )
#                      _____________
#                     <_____________> ___
#                     |             |/ _ \
#                     |               | | |
#                     |               |_| |
#                  ___|             |\___/
#                 /    \___________/    \
#                 \_____________________/
#   ____        __  __           ______                _    
# /  __ \      / _|/ _|          | ___ \              | |   
# | /  \/ ___ | |_| |_ ___  ___  | |_/ /_ __ ___  __ _| | __
# | |    / _ \|  _|  _/ _ \/ _ \ | ___ \ `__/ _ \/ _` | |/ /
# | \__/\ (_) | | | ||  __/  __/ | |_/ / | |  __/ (_| |   < 
#  \____/\___/|_| |_| \___|\___| \____/|_|  \___|\__,_|_|\_\                                                  
#  
#  
#  
# List tool functions
# This script will perform the following automatic functions:
#  
# Inputs asked for...
# File with list of subnets. If not provided it will attempt to find them with ping sweeps for active gateway IPs.
# FQDN Domain Name. If not provided it will attempt to discover it from /etc/reslolv.conf file.
# Username and Password of compromised account if available, to facilitate additional functionality.
#  
# Outputs...
# FQDN Domain Name
# Potential Domain Controller IP addresses
# Null Session Output. Stored in ./domain/ folder
# IPs of systems running SMB, Web ports, Cisco Smart Install, Konica Minolta Printers, & IPMIs Stored in ./scans/ folder.
# Metasploit modules ran to extract creds from...
#  - Cisco Smart Install devices
#  - Konica Minolta Printers
#  - IPMIs
# Generates list of systems with SMB Signing Dissabled. Stored in ./scans/ folder.
# Runs Aquatone to pull screenshots of web servers and zips results as webs.zip in ./scans/ folder.
#  
# If compromised credentials are provided...
# Pull SPN hashes from DC.
# Check DC for GPP Passwords.
# Perform LDAP dump from DC.
# Check for certificate server ESC vulnerabilities.
# Run Bloodhound data collections.
# Places slinky files on writable file shares.
#  
# The following tools are expected to be installed...
#  - enum4linux
#  - nmap
#  - crackmapexec
#  - ldapdomaindump
#  - impacket
#  - metasploit
#  - bloodhound-python
#  - certipy
#  - aquatone
#  - httprobe
#  - chromium
#  
