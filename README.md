# 事前説明
これはXeliによってForkされたLineChatBotです。

# 前提
- [Heroku](https://jp.heroku.com/) のアカウントを取得済みであること。
- Herokuの[CLIツール](https://devcenter.heroku.com/articles/getting-started-with-ruby#set-up)がインストール済みであること。
- [LINE Developer](https://developers.line.me/ja/) 登録が完了し、プロバイダー・channelの作成が完了していること。

# 環境
```
$ ruby -v
ruby 2.7.0p0 (2019-12-25 revision 647ee6f091) [x86_64-darwin19]

$ bundle exec rails -v
Rails 6.0.2.1
```

# Webhook環境の構築
1. リポジトリをクローンする。
```
git clone git@github.com:giftee/intern-line-bot.git
```

2. Herokuにログインする。
```
$ heroku login
heroku: Press any key to open up the browser to login or q to exit:
```

3. heroku上にアプリを作成する。
```
$ heroku create
Creating app... done, ⬢ XXXXX    // XXXXX はランダムな文字列が生成される。
https://XXXXX.herokuapp.com/ | https://git.heroku.com/XXXXX.git

$ git remote -v
heroku	https://git.heroku.com/XXXXX.git (fetch)
heroku	https://git.heroku.com/XXXXX.git (push)
origin	git@github.com:giftee/intern-line-bot.git (fetch)
origin	git@github.com:giftee/intern-line-bot.git (push)
```

4. herokuに資源をデプロイする。
```
$ git push heroku master
```

5. heroku上にアプリが公開されたか確認する。
```
$ heroku open
```

6. LINE Messaging APIにアクセスするためのシークレット情報を登録する。
LINE developer コンソールのChannel基本設定から「Channel Secret」と「アクセストークン」を取得し、以下の通り設定する。
```
$ heroku config:set LINE_CHANNEL_SECRET=*****
$ heroku config:set LINE_CHANNEL_TOKEN=*****
```

# LINE Developerコンソールの設定
LINE DeveloperコンソールのChannel基本設定から、以下を設定。

- Webhook送信: 利用する
- Webhook URL: https://XXXXX.herokuapp.com/callback
- Botのグループトーク参加: 利用する
- 自動応答メッセージ: 利用しない
- 友だち追加時あいさつ: 利用する

※Webhook URLの `https://XXXXX.herokuapp.com` には `heroku create` で生成されたURLを指定する。Webhook URLを設定した後に接続確認ボタンを押して成功したら疎通完了。

# Q&A
## Q. herokuのログが見たい
```
$ heroku logs --tail
```

## Q. masterブランチ以外をherokuにデプロイしたい
```
$ git push heroku feature/xxxxx:master -f
```

# 参考
ローカル環境構築は[こちら](https://github.com/giftee/intern-line-bot/wiki/%E3%83%AD%E3%83%BC%E3%82%AB%E3%83%AB%E7%92%B0%E5%A2%83%E6%A7%8B%E7%AF%89)
