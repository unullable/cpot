require "http"
require "./honeypot"

# Detect exploitation/enumeration attempts
class Honeypot::Detection
    SAFE_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/index.html", "/wiki", "/.well-known/security.txt"]

    def initialize(@request : HTTP::Request)
      @comment = ""
      @known_bots = [
        "Mozi", "androxgh0st", "mirai", "qbot", "sora",
        "arm", "mips", "mipsel", "mpsl", "x86", 
        "sh4", "ppc", "m68k", "spc", "i586", "i686"
      ]
      @known_droppers = [".sh", "/i", "/.i"]
      @known_loaders =  ["wget", "curl", "nc", "base64_decode", "echo"]
    end
        
    private def add_comment(msg : String)
      @comment += "#{msg}\n"
    end
    
    private def detect_path : Bool
      path = @request.path
      return false if SAFE_PATHS.includes?(path)
      if sploit = is_exploit(path)
        add_comment("Exploitation Attempt: #{sploit}")
        return true
      elsif enuminfo = is_enumeration(path)
        add_comment("Enumeration Attempt: #{enuminfo}")
        return true
      else
        add_comment("Accessed: #{path}")
        return true
      end
      false
    end
    
    private def check_loader(str : String) : String?
      @known_loaders.each { |ld| return ld if str.includes?(ld) }
      nil
    end

    private def check_bot_name(str : String) : String?
      @known_bots.each { |botname| return botname if str.includes?(botname) }
      nil
    end

    private def check_dropper(str : String) : String?
      @known_droppers.each { |dropper| return dropper if str.includes?(dropper) }
      nil
    end

    # :showdoc:
    #
    # Detect a loading attempt by performing checks on both body and path.
    private def detect_loader : Bool
      body = @request.body
      return false if body.nil?

      bodyStr = body.gets_to_end

      if check_loader(bodyStr) || check_loader(@request.path)
        add_comment("detected loader attempt: #{bodyStr}")
        return true
      else
        if dropper = check_dropper(bodyStr) || check_dropper(@request.path)
          add_comment("detected dropper attempt: #{dropper}")
        elsif botname = check_bot_name(bodyStr) || check_bot_name(@request.path)
          add_comment("detected known bot: #{botname}")
        end
      end
      false
    end

    # :showdoc:
    #
    # Detect enumeration attempts
    #
    # NOTE: Based on path
    private def is_enumeration(path : String) : String?
      return "Git Enumeration Attempt" if path.includes?(".git")
      return ".Env Enumeration Attempt" if path.includes?(".env")
      return "WordPress Enumeration Attempt" if path.includes?("wp-")
      enumdirs = {
        "/.aws/credentials"                           => "AWS",
        "/aws/.git/config"                            => "AWS",
        "/administrator/manifests/files/joomla.xml"   => "Joomla",
        "/plugins/system/cache/cache.xml"             => "Joomla",
        "/profiles"                                   => "Laravel",
        "/web-console/ServerInfo.jsp"                 => "JBoss",
        "/web-console/Invoker"                        => "JBoss",
        "/invoker/JMXInvokerServlet"                  => "JBoss",
        "/invoker/EJBInvokerServlet"                  => "JBoss",
        "/user/register"                              => "Drupal",
        "/asynchPeople"                               => "Jenkins",
        "/rest/api/2/mypermissions"                   => "JIRA",
        "/rest/api/3/mypermissions"                   => "JIRA",
        "/manager/html"                               => "Tomcat",
        "/manager/text/deploy"                        => "Tomcat",
        "/manager/text/list"                          => "Tomcat"
      }
      return unless enumdirs.has_key?(path)
      return enumdirs[path]
    end
    
    # :showdoc:
    #
    # Detect exploitation attempts
    #
    # NOTE: Based on path
    private def is_exploit(path : String) :  String | Nil
      sploitdirs = {
        "/ws/v1/cluster/apps/new-application"         => "Yarn Hadoop RCE", 
        "/tmUnblock.cgi"                              => "Linksys WRT120N CVE-2025-34037",
        "/hndUnblock.cgi"                             => "Linksys WRT120N CVE-2025-34037",
        "/apply.cgi"                                  => "Linksys WRT160nv2 Command Injection ",
        "/HNAP1/"                                     => "D-Link HNAP1 Command Injection CVE-2019-8318",
        "/cgi-bin/server/server.cgi"                  => "QNAP VioStor NVR CVE-2023-47565",
        "/ctrlt/DeviceUpgrade_1"                      => "Huawei Router HG532 RCE",
        "/GponForm/diag_Form"                         => "GPON Router Command Injection Vulnerability CVE-2018-10561",
        "/goform/set_LimitClient_cfg"                 => "LB Link Command Injection Vulnerability CVE-2023-26801",
        "/UD/act"                                     => "Eir D1000/TR064",
        "/board.cgi"                                  => "VACRON CCTV Board CGI Command Injection",
        "/goform/aspApBasicConfigUrcp"                => "UTT HiPER 840G CVE-2025-7571",
        "/boaform/admin/formLogin"                    => "Authenticated Command Injection on Tenda HG9 Router CVE-2022-30023",
        "/goform/setUsbUnload/.js"                    => "Tenda CVE-2020-10987",
        "/goform/setUsbUnload/"                       => "Tenda CVE-2020-10987",
        "/device.rsp"                                 => "TBK DVR-4104/DVR-4216 CVE-2018-9995",
        "/frame/GetConfig"                            => "D-Link DCS-930L",
        "/cgi-bin/jvsweb.cgi"                         => "Jovision camera",
        "/system.ini"                                 => "P2P wificam remote code execution",
        "/shell"                                      => "Jaws",
        "/cgi-bin/readfile.cgi"                       => "SIEMENS IP-Camera CCMS2025 Password Disclosure",
        "/setSystemCommand"                           => "D-Link DCS-930L Auth RCE",
        "/diagnostic.php"                             => "D-Link DIR-645 & DIR-815 RCE",
        "/apply_sec.cgi"                              => "D-Link PingTest RCE",
        "/ayefeaturesconvert.js"                      => "D-Link DSL-2750B RCE",
        "/cgi-bin/pakfire.cgi"                        => "IPFire Oinkcode RCE",
        "/ping.cgi"                                   => "Netgear DGN2200 RCE",
        "/cgi"                                        => "TP-Link Archer C2 & C20i",
        "/action.php"                                 => "Electric Smart",
        "/actuator/gateway/routes"                    => "Spring Cloud Gateway Actuator Code Injection CVE-2022-22947",
        "/_ignition/execute-solution"                 => "Laravel v8.30.0 (PHP v7.3.25) debug RCE",
        "/login.rsp"                                  => "getDVR (CVE-2018-9995)",
        "/developmentserver/metadatauploader"         => "SAP NetWeaver Visual Composer Metadata Uploader CVE-2025-31324"
      }
      return unless sploitdirs.has_key?(path)
      return sploitdirs[path]
    end
    
    # :showdoc:
    #
    # Detect unusual user agents
    private def detect_ua : Bool
      useragent = begin
                    @request.headers["User-Agent"]
                  rescue
                    return false
                  end
      if  (useragent.starts_with?("Mozilla")  ||
          useragent.starts_with?("Opera")     ||
          useragent.starts_with?("Dalvik")    ||
          useragent.starts_with?("Chrome")    ||
          useragent.starts_with?("Podcasts"))
          return false
      end
      add_comment("Suspicious UA: #{useragent}")
      true
    end
    
    # Judge a request as good or bad
    def judge : String
      detect_path 
      detect_loader 
      detect_ua
      @comment
    end
end
