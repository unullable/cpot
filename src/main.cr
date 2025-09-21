require "./tcp"
require "./honeypot"
require "option_parser"

class CPot
  getter ports : Array(Int32)

  def initialize(@ports)
  end

  def run
    pot = Honeypot::TCP.new @ports
    pot.start
  end
end


bindPorts   = [] of Int32

parser = OptionParser.parse do |parser| 
  parser.banner = "Usage: ./cpot [arguments]"

  parser.on "-h", "--help", "Show help" do 
    puts parser
    exit
  end

  parser.on "-pPORTS", "--ports=PORTS", "TCP ports to bind (e.x: 80,22,23)"  do |str|
    str.split "," {|e| bindPorts << e.to_i}
  end
end

exit if bindPorts.empty?

cpot = CPot.new bindPorts
spawn cpot.run  

puts "[honeypot] Starting TCP Honeypot on ports: #{bindPorts.to_s}"
sleep
