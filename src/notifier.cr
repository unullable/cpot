abstract class Honeypot::Notifier
  def initialize
  end

  # safelify an ipv4
  def safe_ip(ip : String) : String
    ip.gsub('.', "[.]")
  end

  # Get AbuseIPDB for *ip* formatted as HTML
  def abuselink(ip : String) : String
    "<a href=\"https://www.abuseipdb.com/check/#{ip}\">AbuseIPDB</a>"
  end

  # NOTE: overloaded
  def send_notification
    "Not Implemented!"
  end
end
