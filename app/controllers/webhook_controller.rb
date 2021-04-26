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
          # ToDo:保存したい時には保存コマンド・呼び出したい時に呼出コマンドを作りたいかも
          message = {
            type: 'text',
            text: "あなたが投稿した日記を保存しました！　対象：#{event.message['text']}"
          }
          client.reply_message(event['replyToken'], message)

          # JsonBoxにテキストを保存する
          user_id = event['source']['userId']
          message = event.message['text']
          jsonbox_save_message(user_id,message);
        
        when Line::Bot::Event::MessageType::Sticker
          # JsonBoxからランダムなメッセージをスタンプを送ったユーザにpushする
          rand_message = random_message_select
          p ("Message = #{rand_message["id"]}")
          message = {
            "type": "template",
            "altText": "誰かの日記が届いたようです!",
            "template": {
                "type": "buttons",
                "thumbnailImageUrl": "https://joeschmoe.io/api/v1/person" + Time.new.strftime("%H-%M-%S"),
                "imageAspectRatio": "rectangle",
                "imageSize": "cover",
                "imageBackgroundColor": "#FFFFFF",
                "title": "誰かの日記が届いたようです...",
                "text": rand_message["message"],
                "actions": [
                    {
                      "type": "postback",
                      "label": "Like👍",
                      "data": rand_message["id"]
                    }
                ]
            }
          }
          client.reply_message(event['replyToken'], message)
        end
      
      when Line::Bot::Event::Follow
        user_id = event['source']['userId']
        User.set_cache(user_id)
        logger.debug "UserIdList = #{User.get_cache}"

      when Line::Bot::Event::Unfollow
        user_id = event['source']['userId']
        User.delete_cache(user_id)
        logger.debug "UserIdList = #{User.get_cache}"
      

      when Line::Bot::Event::Postback
        #Likeボタンを押された時の処理
        jsonbox_id = event['postback']['data']
        liked_message = jsonbox_like_message(jsonbox_id)
        liked_user_id = decrypt(base64_decode(liked_message["user_id"]))

        #Likeされた人に通知
        message = {
          type: 'text',
          text: "日記がLikeされました！👍"
        }
        client.push_message(liked_user_id, message)

        #Likeした人にメッセージ
        message = {
          type: 'text',
          text: "日記をLikeしました👍"
        }
        client.reply_message(event['replyToken'], message)
        logger.info "Pushed&Replyed liked Message from #{event['userId']} to #{liked_user_id}"

      end
    }
    head :ok
  end

  private

  # Message選択・送信
  def random_message_select
    #JsonBox上からランダムなメッセージを選択
    random_diary = jsonbox_load_message.sample
    params = { "id" => random_diary['_id'], "message" => decrypt(base64_decode(random_diary['message'])) }
    logger.debug("[JSONBOX]:Selected Data #{params}")
    params
  end

  # JsonBox
  DEFAULT_LIKE_NUM = 0

  def jsonbox_save_message(user_id,message)
    #JsonBoxに新しい文章をセーブ
    uri = URI.parse(ENV.fetch("JSONBOX_URL"))
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    params = { user_id: base64_encode(encrypt(user_id)), message: base64_encode(encrypt(message)), like: DEFAULT_LIKE_NUM }
    headers = { "Content-Type" => "application/json" }
    http.post(uri.path, params.to_json, headers)
    logger.info("[JSONBOX]:Posted Data #{params}")
  end

  def jsonbox_load_message
    #JsonBox上の全文のJsonをロード
    uri = URI.parse(ENV.fetch("JSONBOX_URL"))
    response = Net::HTTP.get_response(uri)
    message_list = JSON.parse(response.body)
    logger.debug("[JSONBOX]:Loaded Data #{message_list}")
    message_list
  end

  def jsonbox_like_message(jsonbox_id)
    #メッセージロード(Get)
    uri = URI.parse(ENV.fetch("JSONBOX_URL") + "/" + jsonbox_id)
    response = Net::HTTP.get_response(uri)
    liked_message = JSON.parse(response.body)
    like_num = liked_message["like"].to_i + 1

    #Likeする（Put/Update）
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    params = { user_id: liked_message["user_id"], message: liked_message["message"], like: like_num }
    headers = { "Content-Type" => "application/json" }
    http.put(uri.path, params.to_json, headers).body

    #返り値はLikeされたメッセージ(hash)
    logger.debug("[JSONBOX]:Liked Data #{liked_message}")
    liked_message
  end

  # 暗号・複合化
  def cipher
    @cipher ||= OpenSSL::Cipher::AES.new(256, :CBC)
  end

  def encrypt(data)
    # 暗号機を作る
    enc = cipher
    enc.encrypt
    
    # ENC_PASSWORD,ENC_SALTをもとに鍵・IVを作成・設定
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac(ENV.fetch("ENC_PASSWORD"), ENV.fetch("ENC_SALT"), 2000, enc.key_len + enc.iv_len, "sha256")
    enc.key = key_iv[0, enc.key_len]
    enc.iv = key_iv[enc.key_len, enc.iv_len]

    # 暗号化
    encrypted_data = enc.update(data) + enc.final

    encrypted_data
  end

  def decrypt(data)
    encrypted_data = data
    # 復号器を生成
    dec = cipher
    dec.decrypt

    # ENC_PASSWORD,ENC_SALTをもとに鍵・IVを作成・設定
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac(ENV.fetch("ENC_PASSWORD"), ENV.fetch("ENC_SALT"), 2000, dec.key_len + dec.iv_len, "sha256")
    dec.key = key_iv[0, dec.key_len]
    dec.iv = key_iv[dec.key_len, dec.iv_len]

    # 暗号を復号
    decrypted_data = dec.update(encrypted_data) + dec.final

    decrypted_data.force_encoding(Encoding::UTF_8)
  end

  def base64_encode(data)
    Base64.encode64(data).chomp
  end

  def base64_decode(data)
    Base64.decode64(data).chomp
  end
end
