require 'line/bot'
require 'net/http'
require 'uri'

class WebhookController < ApplicationController
  protect_from_forgery except: [:callback] # CSRF対策無効化
  # 環境変数
  JSONBOX_URL = ENV["JSONBOX_URL"]

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

          # JsonBoxのテスト(FIXME)
          user_id = event['source']['userId']
          message = event.message['text']
          jsonbox_save_message(user_id,message);
          logger.debug "saved message of #{user_id}: [#{message}], Location:#{JSONBOX_URL}"

        when Line::Bot::Event::MessageType::Image, Line::Bot::Event::MessageType::Video
          response = client.get_message_content(event.message['id'])
          tf = Tempfile.open("content")
          tf.write(response.body)
        
        when Line::Bot::Event::MessageType::Sticker
          message = {
            type: 'text',
            text: 'HelloWorld!'
          }
          test_user_id = User.get_cache.first # テストとして一番最初のユーザにpushする
          logger.debug "Pushed message to #{test_user_id}"
          client.push_message(test_user_id, message)
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

  def jsonbox_save_message(user_id,message)
    uri = URI.parse(JSONBOX_URL)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    params = { user_id: user_id, message: message, like: 0 }
    headers = { "Content-Type" => "application/json" }
    http.post(uri.path, params.to_json, headers)
    logger.info(" Posted #{params}")
  end
end
