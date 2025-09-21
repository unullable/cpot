require "log"

module Honeypot::LogToFile
  ACCESS_LOGGER = Log.for "access"
  TELNET_LOGGER = Log.for "telnet"
  SSH_LOGGER    = Log.for "ssh"
  HTTP_LOGGER   = Log.for "http"

  Log.setup do |c|
    access_backend = Log::IOBackend.new(File.new("logs/access.log", "a+"))
    telnet_backend = Log::IOBackend.new(File.new("logs/telnet.log", "a+"))
    ssh_backend = Log::IOBackend.new(File.new("logs/ssh.log", "a+"))
    http_backend = Log::IOBackend.new(File.new("logs/http.log", "a+"))
    c.bind "access.*",  :info, access_backend 
    c.bind "telnet.*",  :info, telnet_backend 
    c.bind "ssh.*",     :info, ssh_backend
    c.bind "http.*",    :info, http_backend
  end
end