#--
# Ruby/ActiveDirectory : Active Directory Interface for Ruby
#
# Copyright (c) 2006-2008 James R. Hunt <james@niftylogic.net>
#++
module ActiveDirectory
	class Computer < Base
		def self.filter # :nodoc:
			Net::LDAP::Filter.eq(:objectClass,'computer')
		end

		def self.required_attributes # :nodoc:
			{ :objectClass => [ 'top', 'person', 'organizationalPerson', 'user', 'computer' ] }
		end

		def hostname
			dNSHostName || name
		end
	end
end
