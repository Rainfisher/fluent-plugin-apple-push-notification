require 'socket'
require 'openssl'

class Fluent::PushNotificationOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('apple_push_notification', self)

  config_param :apn_host, :string,  :default => 'gateway.sandbox.push.apple.com'
  config_param :apn_port, :integer, :default => 2195
  config_param :cert,     :string
  config_param :password, :string
  config_param :keys,     :string
  config_param :columns,  :string
  config_param :timeout,  :integer, :default => 2 * 60 * 60

  def initialize
    super
  end

  def configure(conf)
    super
    @keys = @keys.split(',')
    @columns = @columns.split(',')
    @device_token_index = @columns.index('device_token')
    if @device_token_index.nil?
      raise "device_token_key not in keys"
    end
    @format_proc = Proc.new{|tag, time, record| @keys.map{|k| record[k]}}
    raise "certificate file does not exist" unless File.exists?(@cert)
    @cert_file = File.read(@cert)
    @tcp_socket = nil
    @ssl_socket = nil
    @connect_started_at = nil
    @last_notification_sent_at = nil
  end

  def start
    super
    open_ssl_connection
  end

  def shutdown
    close_ssl_connection
    super
  end

  def format(tag, time, record)
    [tag, time, @format_proc.call(tag, time, record)].to_msgpack
  end

  def write(chunk)
    verify_ssl_connection_is_open
    chunk.msgpack_each { |tag, time, data|
      message = message_for_sending(data)
      @ssl_socket.write(message) if message
    }
    @last_notification_sent_at = Time.now
  end

  def open_ssl_connection
    @connection_started_at = Time.now

    begin
      ctx      = OpenSSL::SSL::SSLContext.new
      ctx.key  = OpenSSL::PKey::RSA.new(@cert_file, @password)
      ctx.cert = OpenSSL::X509::Certificate.new(@cert_file)

      @tcp_socket = TCPSocket.new(@apn_host, @apn_port)
      @ssl_socket = OpenSSL::SSL::SSLSocket.new(@tcp_socket, ctx)
      @ssl_socket.sync = true
      @ssl_socket.connect
    rescue SocketError => error
      raise "Connect error : #{error}"
    end
  end

  def close_ssl_connection
    @connection_started_at = nil
    @ssl_socket.close
    @ssl_socket = nil
    @tcp_socket.close
    @tcp_socket = nil
  end

  def verify_ssl_connection_is_open
    if @ssl_socket.nil?
      open_ssl_connection
    elsif expired?
      close_ssl_connection
      open_ssl_connection
    end
  end

  def expired?
    Time.now - @timeout > @connection_started_at if @connection_started_at
  end

  def apple_json_array(data)
    result = {}
    result['aps'] = {}
    @columns.map { |column, i|
      value = data[i]
      case column
      when 'alert'
      when 'sound'
        value = value.to_s
      when 'badge'
        value = value.to_i
      end
      result['aps'][column] = value
    }
    result.to_json
  end

  def device_token_hexa(device_token)
    return nil if device_token.empty?
    [device_token.delete(' ')].pack('H*')
  end

  def message_for_sending(data)
    token_hexa = device_token_hexa(data[@device_token_index])
    return nil if token_hexa.nil?
    json = apple_json_array(data)
    message = "\0\0 #{token_hexa}\0#{json.length.chr}#{json}"
    #raise "The maximum size allowed for a notification payload is 256 bytes." if message.size.to_i > 256
    return nil if message.size.to_i > 256
    message
  end

end
