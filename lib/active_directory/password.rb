module ActiveDirectory
	class Password
		#
		# Encodes an unencrypted password into an encrypted password
		# that the Active Directory server will understand.
		#
		def self.encode(password)
			("\"#{password}\"".split(//).collect { |c| "#{c}\000" }).join
		end

		#
		# Always returns nil, since you can't decrypt the User's encrypted
		# password.
		#
		def self.decode(hashed)
			nil
		end
	end
end
