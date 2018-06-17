# name: discourse-hibp-password-validator
# about: A password validator using Troy Hunt's Have I Been Pwned API
# version: 0.0.1
# authors: Jeff Wong

require 'net/http'
require 'digest/sha1'

enabled_site_setting :hibp_validation_enabled

after_initialize do
  module ::DiscourseHibp

    class HibpPasswordValidator < ActiveModel::EachValidator

      def validate_each(record, attribute, value)
        return unless record.password_validation_required?
        if pwned_password(value)
          record.errors.add(attribute, :hibp_common)
        end
      end

      def pwned_password(value)
        ::Rails.logger.info "pwned password??"
        hash = Digest::SHA1.hexdigest(value)
        ::Rails.logger.info hash
        hash_start = hash.slice(0,5)
        hash_rest = hash.slice(5..-1)
        uri = URI("https://api.pwnedpasswords.com/range/#{hash_start}")
        result = Net::HTTP.get(uri)
        hibp_hash = {}
        result.split.each do |raw_kv|
          kv = raw_kv.split ":"
          hibp_hash[kv[0]] = kv[1]
        end
        ::Rails.logger.info hibp_hash[hash_rest]
        return hibp_hash[hash_rest]
      end
    end

    class ::User
      validate :hibp_password_validator
      def hibp_password_validator
        DiscourseHibp::HibpPasswordValidator.new(attributes: :password).validate_each(self, :password, @raw_password)
      end
    end
  end
end
