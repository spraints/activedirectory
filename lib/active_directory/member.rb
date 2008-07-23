#--
# Ruby/ActiveDirectory : Active Directory Interface for Ruby
#
# Copyright (c) 2006-2008 James R. Hunt <james@niftylogic.net>
#++

module ActiveDirectory
	module Member
		#
		# Returns true if this member (User or Group) is a member of
		# the passed Group object.
		#
		def member_of?(usergroup)
			group_dns = memberOf
			return false if group_dns.nil? || group_dns.empty?
			#group_dns = [group_dns] unless group_dns.is_a?(Array)
			group_dns.include?(usergroup.dn)
		end

		#
		# Add the member to the passed Group object. Returns true if this object
		# is already a member of the Group, or if the operation to add it succeeded.
		#
		def join(group)
			return false unless group.is_a?(Group)
			group.add(self)
		end

		#
		# Remove the member from the passed Group object. Returns true if this
		# object is not a member of the Group, or if the operation to remove it
		# succeeded.
		#
		def unjoin(group)
			return false unless group.is_a?(Group)
			group.remove(self)
		end
	end
end
