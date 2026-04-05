require "socket"
require "./telnet"
require "./honeypot"
require "./http"
require "./logger"

class Honeypot::TCP
  include Honeypot

  def initialize(@ports : Array(Int32))
    @telnet_ports = [23,2323,1023,10023,5358]
    @http_ports   = [80,81,82,8080,8081,8082,8088,8089,8181,8291,8889,9000,9009,9999]
    @ssh_ports    = [2020,2022,8022,2223,9922,222,2222,22222,24442,10001]
    @adb_ports    = [5555]
  end

  private def handle(port : Int32)
    if @telnet_ports.includes?(port) 
      # Telnet honeypot
      tel = Telnet.new port 
      spawn tel.worker
    elsif @http_ports.includes?(port)
      # HTTP honeypot 
      http = Http.new port
      spawn http.worker
    # Other honeypots
    elsif @ssh_ports.includes?(port)
      puts "[process] spawned sshd proc on port #{port}"
      exec = `python3 ./ssh/ssh.py #{port}`
    elsif @adb_ports.includes?(port)
      # todo: spawn (python) ADB honeypot here
      STDERR.puts("adb not implemented yet!")
    end
  end
  
  # :nodoc:
  def start
    @ports.each do |port| 
      spawn handle(port)
    end
  end
end
