class User
  @@line_uids = []

  def self.set_cache(uid)
      @@line_uids << uid # 配列にキャッシュ
  end

  def self.delete_cache(uid)
    @@line_uids.delete(uid)
  end

  def self.get_cache
    @@line_uids
  end
end