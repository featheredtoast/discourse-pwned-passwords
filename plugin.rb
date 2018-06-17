# name: discourse-pwned-passwords
# about: A password validator using Troy Hunt's Pwned Passwords API
# version: 0.0.1
# authors: Jeff Wong

require 'net/http'
require 'digest/sha1'

enabled_site_setting :pwned_validation_enabled

after_initialize do
  module ::DiscoursePwnedPasswords

    class PasswordValidator < activemodel::eachvalidator

      def validate_each(record, attribute, value)
        return unless record.password_validation_required?
        if pwned_password(value)
          record.errors.add(attribute, :pwned_common)
        end
      end

      def pwned_password(value)
        hash = Digest::SHA1.hexdigest(value).upcase
        hash_start = hash.slice(0,5)
        hash_rest = hash.slice(5..-1)
        uri = URI("https://api.pwnedpasswords.com/range/#{hash_start}")
        result = Net::HTTP.get(uri)
        pwned_hash = {}
        result.split.each do |raw_kv|
          kv = raw_kv.split ":"
          pwned_hash[kv[0]] = kv[1]
        end
        return !!pwned_hash[hash_rest]
      end
    end

    class ::User
      validate :pwned_passwords_validator
      def pwned_passwords_validator
        DiscoursePwnedPasswords::PasswordValidator.new(attributes: :password).validate_each(self, :password, @raw_password)
      end
    end
  end
end
