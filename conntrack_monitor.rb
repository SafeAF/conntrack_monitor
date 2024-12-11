#!/usr/bin/env ruby

require 'set'
require 'resolv'
require 'open3'

# File to store processed IPs
TMP_FILE = "/tmp/processed_ips.txt"

# Initialize a set to track processed IPs
processed_ips = Set.new
if File.exist?(TMP_FILE)
  processed_ips.merge(File.read(TMP_FILE).split("\n"))
end

# Function to resolve hostname
def resolve_hostname(ip)
  begin
    hostname = Resolv.getname(ip)
  rescue Resolv::ResolvError
    hostname = "Unknown"
  end
  hostname
end

# Function to get organization from whois
def get_whois_org(ip)
  whois_output, _status = Open3.capture2("whois #{ip}")
  org_line = whois_output.lines.find { |line| line =~ /^Organization:/i }
  org_line ? org_line.split(":", 2).last.strip : "Unknown Organization"
end

# Main monitoring loop
puts "Monitoring active connections using conntrack (only new IPs)..."

loop do
  # Get the list of active connections from conntrack, suppressing unnecessary messages
  conntrack_output, _status = Open3.capture2("conntrack -L 2>/dev/null")
  ips = conntrack_output.scan(/(?:src|dst)=(\d{1,3}(?:\.\d{1,3}){3})/).flatten.uniq

  ips.each do |ip|
    # Skip IPs already processed
    next if processed_ips.include?(ip)

    # Add IP to the processed set
    processed_ips.add(ip)
    File.open(TMP_FILE, "a") { |file| file.puts(ip) }

    # Resolve hostname
    hostname = resolve_hostname(ip)

    if hostname == "Unknown"
      # Get organization info if hostname is unknown
      org = get_whois_org(ip)
      puts "#{ip} -> #{hostname} (Org: #{org})"
    else
      puts "#{ip} -> #{hostname}"
    end
  end

  # Sleep before the next iteration
  sleep 5
end
