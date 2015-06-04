module GELF
  # Plain Ruby UDP sender.
  class RubyUdpSender
    attr_accessor :addresses

    def initialize(addresses)
      @addresses = addresses
      @i = 0
      @socket = UDPSocket.open
    end

    def send_datagrams(datagrams)
      host, port = @addresses[@i]
      @i = (@i + 1) % @addresses.length
      datagrams.each do |datagram|
        @socket.send(datagram, 0, host, port)
      end
    end

    def close
      @socket.close
    end
  end

  class RubyTcpSocket
    attr_accessor :socket

    def initialize(host, port)
      @host = host
      @port = port
      connect
    end

    def connected?
      if not @connected
        begin
          if @socket.nil?
            @socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          end
          sockaddr = Socket.sockaddr_in(@port, @host)
          @socket.connect_nonblock(sockaddr)
        rescue Errno::EISCONN
          @connected = true
        rescue Errno::EINPROGRESS, Errno::EALREADY
          @connected = false
        rescue SystemCallError
          @socket = nil
          @connected = false
        end
      end
      return @connected
    end

    def connect
      @connected = false
      socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      sockaddr = Socket.sockaddr_in(@port, @host)
      begin
        socket.connect_nonblock(sockaddr)
      rescue Errno::EISCONN
        @connected = true
      rescue SystemCallError
        return false
      end
      @socket = socket
      return true
    end

    def matches?(host, port)
      if @host == host and @port == port
        true
      else
        false
      end
    end

    def close
      @socket.close
      @socket = nil
    end
  end

  class RubyTcpSender
    attr_reader :addresses

    def initialize(addresses)
      @sockets = []
      addresses.each do |address|
        s = RubyTcpSocket.new(address[0], address[1])
        @sockets.push(s)
      end
    end

    def addresses=(addresses)
      addresses.each do |address|
        found = false
        # handle pre existing sockets
        @sockets.each do |socket|
          if socket.matches?(address[0], address[1])
            found = true
            break
          end
        end
        if not found
          s = RubyTcpSocket.new(address[0], address[1])
          @sockets.push(s)
        end
      end
    end

    def send(message)
      while true do
        sent = false
        sockets = @sockets.map { |s|
          if s.connected?
            s.socket
          end
        }
        sockets.compact!
        next unless not sockets.empty?
        begin
          result = select(sockets, sockets, nil, 1)
          if result
            writers = result[1]
            sent = write_any(writers, message)
            readers = result[0]
            read = readable(readers)
          end
          break if sent && read
        rescue SystemCallError, IOError, EOFError
          @sockets.each do |s|
            s.socket.close
            s.socket = nil
            s.connect
          end
        end
      end
    end

    private
    def write_any(writers, message)
      writers.shuffle.each do |w|
        begin
          w.write(message)
          return true
        rescue Errno::EPIPE
          @sockets.each do |s|
            if s.socket == w
              s.socket.close
              s.socket = nil
              s.connect
            end
          end
        end
      end
      return false
    end

    def readable(readers)
      readers.shuffle.each do |r|
        begin
          r.sysread(10)
        rescue EOFError
          @sockets.each do |s|
            if s.socket == r
              s.socket.close
              s.socket = nil
              s.connect
            end
          end
          return false
        end
      end
      return true
    end
  end

  class RubyTcpSSLSocket
    attr_accessor :socket

    require "socket"
    require "openssl"
    require "timeout"

    def initialize(host, port, tls)
      @host = host
      @port = port
      @tls = tls
      connect
    end

    def connected?
      if not @connected
        begin
          if @tcp.nil?
            @tcp = Socket.new(
              Socket::Constants::AF_INET,
              Socket::Constants::SOCK_STREAM,
              Socket::Constants::IPPROTO_IP
            )
            @tcp = TCPSocket.new @host, @port
          end
          if @socket.nil?
            tls_context = OpenSSL::SSL::SSLContext.new
            tls_context.set_params({ :verify_mode=>OpenSSL::SSL::VERIFY_PEER})
            if @tls == GELF::TLS::TRUE
              begin
                jruby-openssl = Gem.latest_spec_for('jruby-openssl').version
              rescue
                jruby-openssl = nil
              end
              if openssl
                if jruby-openssl >= Gem::Version.new('0.9.7')
                  tls_context.set_params({ :ssl_version => 'TLSv1_2'})
                else
                  tls_context.set_params({ :ssl_version => 'TLSv1'})
                end
              else
                tls_context.set_params({ :ssl_version => 'TLSv1_2'})
              end
            end
            @socket = OpenSSL::SSL::SSLSocket.new(@tcp,tls_context)
            @socket.sync_close = true
            @socket.connect
          end
          @connected = true
        rescue Errno::EISCONN
          @connected = true
        rescue Errno::EINPROGRESS, Errno::EALREADY
          @connected = false
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::ETIMEDOUT
          @socket = nil
          @connected = false
        rescue OpenSSL::SSL::SSLError
          @socket = nil
          @connected = false
        rescue SystemCallError
          @socket = nil
          @connected = false
        end
      end
      return @connected
    end

    def connect
      begin
        @connected = false
        tcp = Socket.new(
          Socket::Constants::AF_INET,
          Socket::Constants::SOCK_STREAM,
          Socket::Constants::IPPROTO_IP
        )
        tls_context = OpenSSL::SSL::SSLContext.new
        tls_context.set_params({ :verify_mode=>OpenSSL::SSL::VERIFY_PEER})
        if @tls == GELF::TLS::TRUE
          begin
            jruby-openssl = Gem.latest_spec_for('jruby-openssl').version
          rescue
            jruby-openssl = nil
          end
          if openssl
            if jruby-openssl >= Gem::Version.new('0.9.7')
              tls_context.set_params({ :ssl_version => 'TLSv1_2'})
            else
              tls_context.set_params({ :ssl_version => 'TLSv1'})
            end
          else
            tls_context.set_params({ :ssl_version => 'TLSv1_2'})
          end
        end
        tcp = TCPSocket.new(@host, @port)
        socket = OpenSSL::SSL::SSLSocket.new(tcp,tls_context)
        socket.sync_close = true
        socket.connect
      rescue Errno::EISCONN
        @connected = true
      rescue Errno::EINPROGRESS, Errno::EWOULDBLOCK
        return false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        return false
      rescue OpenSSL::SSL::SSLError
        return false
      rescue SystemCallError
        return false
      end
      @tcp = tcp
      @socket = socket
      return true
    end

    def matches?(host, port)
      if @host == host and @port == port
        true
      else
        false
      end
    end

    def close
      @socket.close
      @socket = nil
      @tcp = nil
    end
  end

  class RubyTcpSSLSender
    attr_reader :addresses

    def initialize(addresses)
      @sockets = []
      addresses.each do |address|
        s = RubyTcpSSLSocket.new(address[0], address[1], address[2])
        @sockets.push(s)
      end
    end

    def addresses=(addresses)
      addresses.each do |address|
        found = false
        @sockets.each do |socket|
          if socket.matches?(address[0], address[1], address[2])
            found = true
            break
          end
        end
        if not found
          s = RubyTcpSSLSocket.new(address[0], address[1], address[2])
          @sockets.push(s)
        end
      end
    end

    def send(message)
      while true do
        sent = false
        timeout = 1
        sockets = @sockets.map { |s|
          if s.connected?
            s.socket
          end
        }
        sockets.compact!
        next unless not sockets.empty?
        begin
          result = select(sockets, sockets, nil, timeout)
          if result
            writers = result[1]
            sent = write_any(writers, message)
            readers = result[0]
            read = readable(readers)
          end
          break if sent && read
        rescue SystemCallError, IOError, EOFError, OpenSSL::SSL::SSLError
          @sockets.each do |s|
            s.socket.close
            s.socket = nil
            s.connect
          end
        end
      end
    end

    private
    def write_any(writers, message)
      writers.shuffle.each do |w|
        begin
          w.write(message)
          return true
        rescue Errno::EPIPE, OpenSSL::SSL::SSLError
          @sockets.each do |s|
            if s.socket == w
              s.socket.close
              s.socket = nil
              s.connect
            end
          end
        end
      end
      return false
    end

    def readable(readers)
      readers.shuffle.each do |r|
        begin
          r.sysread(10)
        rescue EOFError
          @sockets.each do |s|
            if s.socket == r
              s.socket.close
              s.socket = nil
              s.connect
            end
          end
          return false
        end
      end
      return true
    end
  end

end
