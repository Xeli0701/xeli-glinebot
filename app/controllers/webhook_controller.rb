require 'line/bot'
require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'base64'

class WebhookController < ApplicationController
  protect_from_forgery except: [:callback] # CSRF対策無効化

  def client
    @client ||= Line::Bot::Client.new { |config|
      config.channel_secret = ENV["LINE_CHANNEL_SECRET"]
      config.channel_token = ENV["LINE_CHANNEL_TOKEN"]
    }
  end

  def callback
    body = request.body.read

    signature = request.env['HTTP_X_LINE_SIGNATURE']
    unless client.validate_signature(body, signature)
      head 470
    end

    events = client.parse_events_from(body)
    events.each { |event|
      
      case event
      when Line::Bot::Event::Message
        case event.type
        when Line::Bot::Event::MessageType::Text
          message = {
            type: 'text',
            text: event.message['text']
          }
          client.reply_message(event['replyToken'], message)

          # JsonBoxにテキストを保存する
          user_id = event['source']['userId']
          message = event.message['text']
          jsonbox_save_message(user_id,message);
        
        when Line::Bot::Event::MessageType::Sticker
          # JsonBoxから取得し、返すテスト
          # JsonBoxからメッセージ一覧を取得し、最初のメッセージを取り出す
          message_list = jsonbox_load_message
          decrypted_message = decrypt(message_list.first["message"]).force_encoding(Encoding::UTF_8)
          message = {
            type: 'text',
            text: decrypted_message
          }
          test_user_id = User.get_cache.first # テストとして一番最初のユーザにpushする
          client.push_message(test_user_id, message)
          logger.debug "Pushed message [#{message}] to #{test_user_id}"
        end
      
      when Line::Bot::Event::Follow
        user_id = event['source']['userId']
        User.set_cache(user_id)
        logger.debug "UserIdList = #{User.get_cache}"

      when Line::Bot::Event::Unfollow
        user_id = event['source']['userId']
        User.delete_cache(user_id)
        logger.debug "UserIdList = #{User.get_cache}"
      end
    }
    head :ok
  end

  private

  # JsonBoxでの環境変数
  JSONBOX_URL = ENV.fetch("JSONBOX_URL")
  DEFAULT_LIKE_NUM = 0

  def jsonbox_save_message(user_id,message)
    uri = URI.parse(JSONBOX_URL)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    params = { user_id: encrypt(user_id), message: encrypt(message), like: DEFAULT_LIKE_NUM }
    headers = { "Content-Type" => "application/json" }
    http.post(uri.path, params.to_json, headers)
    logger.info(" [JSONBOX]:Posted Data #{params} , Location:#{JSONBOX_URL}")
  end

  def jsonbox_load_message
    uri = URI.parse(JSONBOX_URL)
    response = Net::HTTP.get_response(uri)
    message_list = JSON.parse((response.body))
    logger.debug(" [JSONBOX]:Loaded Data #{message_list} , Location:#{JSONBOX_URL}")
    message_list
  end

  # 暗号・複合での環境変数
  ENC_PASSWORD = ENV.fetch("ENC_PASSWORD")
  ENC_SALT = ENV.fetch("ENC_SALT")

  def encrypt(data)
    # 暗号機を作る
    enc = OpenSSL::Cipher::AES.new(256, :CBC)
    enc.encrypt
    
    # ENC_PASSWORD,ENC_SALTをもとに鍵・IVを作成・設定
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac(ENC_PASSWORD, ENC_SALT, 2000, enc.key_len + enc.iv_len, "sha256")
    enc.key = key_iv[0, enc.key_len]
    enc.iv = key_iv[enc.key_len, enc.iv_len]

    # 暗号化 & Base64Encode
    encrypted_data = enc.update(data) + enc.final
    encrypted_data = Base64.encode64(encrypted_data).chomp

    encrypted_data
  end

  def decrypt(data)
    encrypted_data = Base64.decode64(data)
    # 復号器を生成
    dec = OpenSSL::Cipher::AES.new(256, :CBC)
    dec.decrypt

    # ENC_PASSWORD,ENC_SALTをもとに鍵・IVを作成・設定
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac(ENC_PASSWORD, ENC_SALT, 2000, dec.key_len + dec.iv_len, "sha256")
    dec.key = key_iv[0, dec.key_len]
    dec.iv = key_iv[dec.key_len, dec.iv_len]

    # 暗号を復号
    decrypted_data = dec.update(encrypted_data) + dec.final

    decrypted_data
  end

end
